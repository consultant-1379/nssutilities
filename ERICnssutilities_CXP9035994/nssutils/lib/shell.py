import Queue
import collections
import errno
import json
import os
import random
import subprocess
import sys
import threading
import time
from stat import S_ISDIR

import paramiko
from paramiko.ssh_exception import AuthenticationException, ProxyCommandFailure

import cache
import config
import exception
import filesystem
import log
import mutexer
import timestamp
from nssutils.lib.exceptions import ShellCommandReturnedNonZero
from nssutils.lib.network import is_host_pingable

MAX_CONNECTIONS_PER_REMOTE_HOST = 10
DEFAULT_VM_SSH_KEYPATH = "/root/.ssh/vm_private_key"
connection_mgr = None
COMMAND_TIMEOUT_RC = 177
COMMAND_CONNECTION_CLOSED_RC = 255
COMMAND_EXCEPTION_RC = 211


class ConnectionPoolManager(object):
    id_counter = 1

    def __init__(self):
        """
        ConnectionPoolManager constructor

        :returns: a shell.ConnectionPoolManager instance
        :rtype: shell.ConnectionPoolManager

        """

        self.remote_connection_pool = {}

    def get_connection(self, host, user, password=None, new_connection=False, ssh_identity_file=None, ms_proxy=False, allow_agent=True, look_for_keys=True):
        """
        Get a connection from the connection pool, creating one if none are available and the queue isn't full

        NOTE: Waits up to 30s for a connection to become available to return, otherwise returns None

        :param host: IP address or hostname of the remote host on which the command is to be executed
        :type host: string
        :param user: Username of the account to use for the SSH connection
        :type user: string
        :param password: Password for the aforementioned user account (optional; not required for public key based connections)
        :type password: string
        :param new_connection: set to True to set up a new connection.
        :type new_connection: bool
        :param ssh_identity_file: the filename of optional private key to try for authentication
        :type ssh_identity_file: string
        :param ms_proxy: set to True to create an open socket or socket-like object (such as a `.Channel`) to use for communication to the target host
        :type ms_proxy: bool
        :param allow_agent: set to False to disable connecting to the SSH agent
        :type allow_agent: bool
        :param look_for_keys: set to False to disable searching for discoverable private key files in ``~/.ssh/``
        :type look_for_keys: bool

        :returns: a connection from the connection pool, creating one if none are available and the queue isn't full
        :rtype: paramiko.Client

        """
        if new_connection:
            return self._establish_connection(host, user, password, ssh_identity_file=ssh_identity_file, ms_proxy=ms_proxy, allow_agent=allow_agent, look_for_keys=look_for_keys)

        create_connection = False

        # Use a mutex to synchronize access to the remote session dictionary
        with mutexer.mutex("shell-connection-manager-get-connection"):

            if host not in self.remote_connection_pool:
                self.remote_connection_pool[host] = {}
                self.remote_connection_pool[host]['available'] = Queue.Queue(MAX_CONNECTIONS_PER_REMOTE_HOST)
                self.remote_connection_pool[host]['used'] = collections.deque()

            # Pull the connection queue for this host from the dictionary
            available = self.remote_connection_pool[host]['available']
            used = self.remote_connection_pool[host]['used']

            # Try to pull a connection from the queue if one is available
            connection = None
            checked_connections = collections.deque()
            while connection is None:
                try:
                    possible_connection = available.get(False)
                    if hasattr(possible_connection, 'user') and possible_connection.user == user:
                        connection = possible_connection
                    # Following required for rpm upgrades where we have connections in our pool that do not have the
                    # user attribute set and so it just works like it did previously
                    elif not hasattr(possible_connection, 'user'):
                        connection = possible_connection
                    else:
                        checked_connections.append(possible_connection)
                except Queue.Empty:
                    break

            for checked_connection in checked_connections:
                available.put(checked_connection)

            # If no connection was immediately available...
            if connection is None or not self.is_connected(connection):
                # Cycle through the used queue and make sure there are no dead connections in there
                for _ in range(1, len(used) + 1):
                    connection = used.pop()
                    if self.is_connected(connection):
                        used.append(connection)

                # If the length of the available and used queues is less than max connections, let's create a new connection
                if (available.qsize() + len(used)) < MAX_CONNECTIONS_PER_REMOTE_HOST:
                    create_connection = True
                # Otherwise, if the queue is full, we just need to sit and wait for a connection to free up, and remove
                # it from the queue to allow us to create another one with the correct user
                else:
                    try:
                        # pop one off the queue to make room for a new user connection)
                        available.get(True, 120)
                        create_connection = True

                    except Queue.Empty:
                        connection = None

                    # Check to see if we got a dead connection; if so, let's create a new one
                    if connection is not None and not self.is_connected(connection):
                        create_connection = True

            # Create a new connection if we need to
            if create_connection:
                connection = self._establish_connection(host, user, password, ssh_identity_file=ssh_identity_file, ms_proxy=ms_proxy, allow_agent=allow_agent, look_for_keys=look_for_keys)

                if connection is not None:
                    total_connections = available.qsize() + len(used) + 1
                    log.logger.debug("There are {0} connections in the connection pool for remote host {1}".format(total_connections, host))

            # If we have a valid connection, make sure it is added to the used list to reflect that it's in use
            if connection is not None:
                used.append(connection)

        return connection

    def return_connection(self, host, connection, keep_connection_open=False):
        """
        Returns a connection to the connection pool if the pool isnt full and its a valid connection otherwise just close the connection

        :param host: str, IP address or hostname of the remote host on which the command is to be executed
        :param connection: paramiko.Client, Connection to be returned to the connection pool
        :param keep_connection_open: bool, False if you want the connection to close after you return it else True

        :return: None
        """

        with mutexer.mutex("shell-connection-manager-return-connection"):
            # Once pool is managed properly - take out independent calls to _establish_connection when they dont want to
            # use the pool and just want a once off connection. This will be implemented as per JIRA TORF-244099.
            # Then we should remove this if condition as once we only use the pool,
            # the host will always be in self.remote_connection_pool
            if host in self.remote_connection_pool:
                available = self.remote_connection_pool[host]["available"]
                used = self.remote_connection_pool[host]["used"]

                # Once JIRA TORF-241993 is done then this try catch should be removed as there is no need for it.
                try:
                    used.remove(connection)
                except ValueError:
                    log.logger.debug(
                        "The specified connection with id: {0} did not exist in the used connection queue.".format("1"))

                if keep_connection_open:
                    if self.is_connected(connection):
                        try:
                            available.put(connection, False)
                            return
                        except Queue.Full:
                            log.logger.debug("The available connections queue is already full and therefore "
                                             "cant add the valid connection with id {0}.".format("1"))

            try:
                log.logger.debug("Attempting to close connection with id: '{0}' to host '{1}'.".format(connection.id, connection.host))
                connection.close()
                log.logger.debug("Connection with id: '{0}' to host '{1}' closed successfully.".format(connection.id, connection.host))
            except Exception as e:
                log.logger.debug("Error closing connection with id: '{0}' to host '{1}'. Error: {2}".format("1", host, e))

    def is_connected(self, connection):
        """
        Checks to see if the connection to the remote host is active and established or not

        rtype: boolean

        """

        result = False

        # If we encounter an exception checking the connection, swallow it since we're going to report a false anyway
        try:
            if connection is not None and connection.get_transport().is_authenticated():
                result = True
        except Exception as e:
            log.logger.debug("Exception in shell.ConnectionPoolManager.is_connected: {0}".format(str(e)))

        return result

    def _establish_connection(self, host, user, password=None, verbose=True, retry=True, ssh_identity_file=None, ms_proxy=False, allow_agent=True, look_for_keys=True):
        """
        Establishes a new SSH connection

        :type host: string
        :param host: IP address or hostname of the remote host on which the command is to be executed
        :type user: string
        :param user: Username of the account to use for the SSH connection
        :type password: string
        :param password: Password for the aforementioned user account (optional; not required for public key based connections)
        :type ssh_identity_file: string
        :param ssh_identity_file: the filename of optional private key to try for authentication
        :type ms_proxy: bool
        :param ms_proxy: set to True to create an open socket or socket-like object (such as a `.Channel`) to use for communication to the target host
        :type allow_agent: bool
        :param allow_agent: set to False to disable connecting to the SSH agent
        :type look_for_keys: bool
        :param look_for_keys: set to False to disable searching for discoverable private key files in ``~/.ssh/``

        :raises: SSHException, BadHostKeyException, NoValidConnectionsError

        :returns: a new SSH connection
        :rtype: paramiko.Client

        """
        ssh_identity_file = ssh_identity_file or DEFAULT_VM_SSH_KEYPATH  # To make backward compatibility. This should be passed by caller

        log.logger.debug("Attempting to establish SSH connection to remote host {0} as user {1}".format(host, user))

        # Establish connection with remote host

        connection = paramiko.SSHClient()
        connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connection.load_system_host_keys()
        retryAuthentication = True
        proxy = None
        key_filename = None
        if ssh_identity_file is not None:
            if ms_proxy:
                if cache.is_emp():
                    proxy = paramiko.ProxyCommand("ssh -i {0} -x -a -q -o StrictHostKeyChecking=no cloud-user@{1} "
                                                  "nc {2} 22".format(ssh_identity_file, cache.get_emp(), host))
                else:
                    proxy = paramiko.ProxyCommand("ssh -x -a -q -o StrictHostKeyChecking=no root@{0} nc {1} 22"
                                                  .format(cache.get_ms_host(), host))
            key_filename = ssh_identity_file if filesystem.does_file_exist(ssh_identity_file) else None

        try:
            connection.connect(host, username=user, password=password, key_filename=key_filename, timeout=7, sock=proxy, allow_agent=allow_agent, look_for_keys=look_for_keys)
        except (paramiko.BadHostKeyException, paramiko.SSHException, AuthenticationException) as e:
            log.logger.debug("Exception {0}, in host: {1}".format(e.message, host))
            if isinstance(e, paramiko.BadHostKeyException):
                run_local_cmd("ssh-keygen -R {0}".format(host))
            elif isinstance(e, AuthenticationException):
                if ms_proxy:
                    log.logger.debug("Authentication failed, getting vm_private_key from MS")
                    run_local_cmd('scp root@{0}:/root/.ssh/vm_private_key ~/.ssh'.format(cache.get_ms_host()))
                else:
                    retryAuthentication = False
            if retry and retryAuthentication:
                return self._establish_connection(host, user, password=password, verbose=verbose, retry=False, ssh_identity_file=ssh_identity_file, ms_proxy=ms_proxy, allow_agent=allow_agent, look_for_keys=look_for_keys)
            raise

        # Force remote side to allocate pseudo-terminal for better job control
        if verbose:
            log.logger.debug("Initial connection established; requesting remote end to allocate pty...")

        transport = connection.get_transport()
        channel = transport.open_session()
        channel.get_pty()

        if connection is not None:
            with mutexer.mutex("shell-establish-connection-set-id"):
                connection.id = ConnectionPoolManager.id_counter
                ConnectionPoolManager.id_counter += 1

            connection.host = host
            connection.user = user
            connection.timed_out = False

        if verbose:
            log.logger.debug("Established SSH connection {0}@{1} [connection ID {2}]".format(user, host, connection.id))

        return connection


class Executor(object):

    def __init__(self, cmd_obj):
        """
        Executor abstract base class constructor

        :param cmd_obj: Command to be executed
        :type cmd_obj: shell.Command

        :returns: a shell.Executor instance
        :rtype: shell.Executor

        """

        self.cmd_obj = cmd_obj
        self.execution_host = None

    def execute(self):
        """
        Executes command based on the attributes specified in the object instance

        :returns: a shell.Response instance containing output, return code, etc.
        :rtype: shell.Response

        """

        # Initialize command attributes (or reset them in the case of re-exeuction of a command)
        self.cmd_obj.initialize_attributes()

        # Set the execution context in the command so the command has an idea where he was executed
        self.cmd_obj.execution_host = self.execution_host

        # Loop until we get a successful execution or we run out of attempts
        self.cmd_obj.finished = False

        while not self.cmd_obj.finished:
            # Do any necessary pre-execute setup
            self.cmd_obj.pre_execute()

            # Execute the command
            self.execute_command()

            # Do any post-execute teardown
            self.cmd_obj.post_execute()

        return self.cmd_obj.response

    def execute_command(self):
        """
        Executes command

        """
        raise NotImplementedError("This method should be overridden by the derived class")


class RemoteExecutor(Executor):

    def __init__(self, cmd_obj, connection, **kwargs):
        """
        RemoteExecutor constructor

        :type cmd_obj: shell.Command
        :param cmd_obj: Command to be executed

        :returns: a shell.RemoteExecutor instance
        :rtype: shell.RemoteExecutor

        """

        super(RemoteExecutor, self).__init__(cmd_obj)
        self.connection = connection
        self.execution_host = connection.host
        self.timer = None
        # Ability to pass parameter for get_pty as workaround for limitation in ENM as per TORF-151381,
        # i.e. use pseudo-terminal when running certain ENM python scripts via ssh connection
        self.get_pty = kwargs.pop("get_pty", False)
        # threading.Timer only kills the SSH connection not the netsim pipe spawned process for some reason.
        # Underlying issue of why processes sent through netsim pipe are hanging still exists.
        self.add_linux_timeout = kwargs.pop("add_linux_timeout", False)

        # Remote retries are not enabled by default
        cmd_obj.allow_retries = False

    def execute_command(self):
        """
        Creates SSH connection to remote host and executes command, returning a shell.Response instance containing output, return code, etc.

        :returns: a shell.Response instance containing output, return code, etc.
        :rtype: shell.Response

        """

        # Start the timer thread to make sure that the remote command doesn't hang and create a deadlock
        self._start_timer(self.connection)

        # Check if the command uses sudo, if it does set get_pty argument to exec_command to True
        if not self.get_pty and self.cmd_obj.cmd.startswith('sudo') or not self.get_pty and self.cmd_obj.cmd.startswith('/usr/bin/sudo'):
            # NOTE: We are going to run the sudo command with pseudo terminal remotely. This has
            # its own side effects. If the output is unexpected please have a look at:
            # http://unix.stackexchange.com/a/122624
            self.get_pty = True

        if self.add_linux_timeout:
            self.cmd_obj.cmd = "timeout --kill-after={0} {0} {1}".format(self.cmd_obj.timeout, self.cmd_obj.cmd)

        # Execute the command and immediately close stdin
        try:
            (stdin, stdout, stderr) = self.connection.exec_command(self.cmd_obj.cmd, timeout=self.cmd_obj.timeout, get_pty=self.get_pty)
            stdin.close()
            if self.cmd_obj.async:
                return

            # Attempt to get the return code and output
            self.cmd_obj.response._rc = stdout.channel.recv_exit_status()
            self.cmd_obj.response._stdout = stdout.read() + stderr.read()

            stdout.close()
            stderr.close()
        except ProxyCommandFailure:
            log.logger.error('Bug in paramiko preventing the tunnel to close if this exception occurs resulting in socket spiking the CPU usage, check https://github.com/paramiko/paramiko/issues/495')
            self.connection.close()
            self.cmd_obj.response._rc = -1
            self.cmd_obj.response._stdout = ""
        except Exception as err:
            log.logger.error("ERROR: {0}".format(str(err)))
            exception.process_exception("Exception raised while running remote command: '{0}'".format(self.cmd_obj.cmd))
            self.cmd_obj.response._rc = -1
            self.cmd_obj.response._stdout = ""
        finally:
            self._command_cleanup()

        # If the command timed out and was killed, update the rc
        if self.connection.timed_out:
            self.cmd_obj.response._rc = COMMAND_TIMEOUT_RC
            self.cmd_obj.response._stdout = ""
        # If the command was interrupted or the remote host died
        elif self.cmd_obj.response._rc == -1:
            self.cmd_obj.response._rc = COMMAND_CONNECTION_CLOSED_RC
            self.cmd_obj.response._stdout = ""

    def _start_timer(self, connection):
        """
        Creates and starts command timer and defines callback function to be invoked if timeout expires

        :param connection: Connection to be terminated
        :type connection: paramiko.Client

        :returns: void

        """

        # Spawn the timer thread
        self.timer = threading.Timer(self.cmd_obj.current_timeout, remote_timeout_killer, [connection])
        self.timer.daemon = True
        self.timer.start()

    def _command_cleanup(self):
        """
        Kills the timer thread

        :returns: void

        """

        # Make sure the timer thread is finished
        if self.timer is not None and self.timer.is_alive():
            self.timer.cancel()
            self.timer = None


class LocalExecutor(Executor):

    def __init__(self, cmd_obj):
        """
        LocalExecutor constructor

        :param cmd_obj: Command to be executed
        :type cmd_obj: shell.Command

        :returns: a shell.LocalExecutor instance
        :rtype: shell.LocalExecutor

        """

        super(LocalExecutor, self).__init__(cmd_obj)
        self.timer = None
        self.execution_host = "localhost"

    def execute_command(self):
        """
        Opens subprocess and executes the local command, returning a shell.Reponse instance containing output, return code, etc.

        :returns a shell.Response instance containing output, return code, etc.
        :rtype: shell.Response

        """

        # Kick off the subprocess to execute the command
        if self.cmd_obj.activate_virtualenv:
            prefix = 'source %s;' % os.path.join(os.path.dirname(sys.executable), 'activate')
        else:
            prefix = ''
        proc = subprocess.Popen(prefix + self.cmd_obj.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, cwd=self.cmd_obj.cwd)

        if hasattr(proc, "pid"):
            self.cmd_obj.response._pid = proc.pid

        if self.cmd_obj.async:
            return

        # Start the timer thread to make sure that the command doesn't hang and create a deadlock
        self._start_timer(proc)

        # Kick off the process and wait for it to finish
        try:
            self.cmd_obj.response._stdout = proc.communicate()[0]
            self.cmd_obj.response._rc = proc.returncode

        except Exception as err:
            log.logger.error("ERROR: {0}".format(str(err)))
            exception.process_exception("Exception raised while running local command: '{0}'".format(self.cmd_obj.cmd))
            self.cmd_obj.response._rc = COMMAND_EXCEPTION_RC
            self.cmd_obj.response._stdout = ""
        finally:
            self._command_cleanup(proc)

    def _start_timer(self, proc):
        """
        Creates and starts command timer and defines callback function to be invoked if timeout expires

        :param proc: suprocess object which interacts with the shell
        :type proc: subprocess.Popen

        :returns: void

        """

        # Spawn the timer thread
        self.timer = threading.Timer(self.cmd_obj.current_timeout, local_timeout_killer, [proc])
        self.timer.daemon = True
        self.timer.start()

    def _command_cleanup(self, proc):
        """
        Kills subprocess and timer if they are still running

        :param proc: suprocess object which interacts with the shell
        :type proc: subprocess.Popen

        :returns: void

        """

        # If for some reason the process hasn't terminated, kill it
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception as err:
            log.logger.error("ERROR: {0}".format(str(err)))
            exception.process_exception("Exception raised while trying to kill process")

        # Make sure the timer thread is finished
        if self.timer is not None and self.timer.is_alive():
            self.timer.cancel()
            self.timer = None


class Command(object):

    def __init__(self, cmd, log_cmd=True, timeout=None, allow_retries=True, check_pass=False, cwd=None,
                 activate_virtualenv=False, retry_limit=None, async=False):
        """
        Command Constructor

        :param cmd: The shell command to be execute
        :type cmd: string
        :param log_cmd: Flag controlling whether command is to be logged to debug log (defaults to True)
        :type log_cmd: boolean
        :param timeout: Length of time to allow command to run before terminating the command
        :type timeout: int
        :param allow_retries: Flag controlling whether the command is to be retried if it times out (defaults to True)
        :type allow_retries: boolean
        :param check_pass: Flags whether the check for an rc of 0 after executing command (defaults to False)
        :type check_pass: boolean
        :param cwd: Option to change the current working directory when executing the command (defaults to None)
        :type cwd: string
        :param activate_virtualenv: Flags if virtualenv needs to be activated prior to running the command
        :type activate_virtualenv: boolean
        :param async: Flags whether to wait for a command response or just run the command and return
        :type async: boolean

        :returns: an instance of shell.Command
        :rtype: shell.Command

        """

        self.cmd = cmd
        self.log_cmd = log_cmd
        self.timeout = timeout
        self.check_pass = check_pass
        self.allow_retries = allow_retries
        self.cwd = cwd
        self.async = async

        self.retry_count = 1
        self.retry_limit = retry_limit
        self.execution_host = None
        self.finished = False
        self.current_timeout = self.timeout
        self.response = None
        self.activate_virtualenv = activate_virtualenv

    def initialize_attributes(self):
        """
        Sets attributes to their initial state before executing the command

        :returns: void

        """

        self.retry_count = 1
        self.execution_host = None

        if self.retry_limit is None:
            if self.allow_retries:
                self.retry_limit = 2
            else:
                self.retry_limit = 1

        if self.timeout is None:
            self.timeout = 60

    def _set_attributes(self):
        """
        Sets or resets attributes to default state before each command execution (including retries)

        :returns: void

        """

        self.current_timeout = self.timeout

        self.finished = False
        self.response = Response(command=self.cmd)

    def pre_execute(self):
        """
        Performs any setup and/or logging tasks to be done before command execution is started

        :returns: void

        """

        # Set attributes or reset them in the event that a command is being rerun
        self._set_attributes()

        # Adjust the timeout if necessary
        self._set_command_timeout()

        if self.log_cmd:
            log.logger.debug("Executing command on {0}: '{1}' [timeout {2}s]".format(self.execution_host, self.cmd, self.current_timeout))
        # Record the start timestamp
        self.response._start_timestamp = timestamp.get_current_time()

    def post_execute(self):
        """
        Performs any teardown and/or logging tasks after command execution

        :returns: void

        """

        # Figure out the elapsed execution time
        self.response._end_timestamp = timestamp.get_current_time()
        self.response._elapsed_time = timestamp.get_elapsed_time(self.response._start_timestamp)

        # If command timed out or the connection was closed, log the error
        if self.response.rc in [COMMAND_TIMEOUT_RC, COMMAND_CONNECTION_CLOSED_RC, COMMAND_EXCEPTION_RC]:
            self._log_error_result()

            if self._can_retry():
                self._sleep_between_attempts()
        else:
            if self.log_cmd:
                # Log the successful execution
                log.logger.log_cmd("Executed command '{0}' on {1} [elapsed time {2}s]".format(self.cmd, self.execution_host, self.response.elapsed_time), str(self.response.rc), self.response.stdout)
            self.finished = True

        if self.finished and self.check_pass:
            self._check_command_passed()

    def _set_command_timeout(self):
        """
        Sets timeout value for the command

        :returns: void

        """

        if self.retry_count > 1:
            self.current_timeout = self.current_timeout * 2
            log.logger.debug("Increasing command execution timeout to {0}s for next execution attempt...".format(self.current_timeout))

    def _check_command_passed(self):
        """
        Checks command for a return code of 0 and raises a RuntimeError if the rc is not 0

        :returns: void

        """

        if self.response.rc != 0:
            error_message = "Command was expected to pass, but produced a non-zero return code [{0}]; CMD: {1}".format(self.response.rc, self.cmd)
            raise RuntimeError(error_message)

    def _sleep_between_attempts(self):
        """
        Sleeps between command execution attempts

        :returns: void

        """

        # Sleep for a small bit to give the system some breathing room
        sleep_interval = float("%.2f" % (random.random() * 4))
        log.logger.debug("Sleeping for %s seconds before re-attempting..." % sleep_interval)

        time.sleep(sleep_interval)

    def _can_retry(self):
        """
        Checks whether a command that has errored can be run again

        rtype: boolean

        """

        if not self.allow_retries or self.retry_count == self.retry_limit:
            result = False
            self.finished = True
        else:
            result = True
            self.retry_count += 1

        return result

    def _log_error_result(self):
        """
        Logs information to debug log on failed command execution attempt

        rtype: void

        """

        with mutexer.mutex("log-command-error-result"):
            if self.response.rc == COMMAND_TIMEOUT_RC:
                log.logger.debug("   ERROR: Process exceeded timeout and was forcibly terminated [attempt {0}/{1}]".format(self.retry_count, self.retry_limit))
                log.logger.debug(" TIMEOUT: {0}s".format(self.current_timeout))
            elif self.response.rc == COMMAND_CONNECTION_CLOSED_RC:
                log.logger.debug("   ERROR: Process terminated unexpectedly (likely due to resource starvation)")

            log.logger.debug("     CMD: {0}".format(self.cmd))
            log.logger.debug("  STDOUT: {0}".format(self.response.stdout))
            log.logger.debug("      RC: {0}".format(self.response.rc))
            log.logger.debug("CMD TIME: {0}s".format(self.response.elapsed_time))


class Response(object):

    def __init__(self, rc=None, stdout=None, elapsed_time=None, command=None, pid=None):
        """
        Response Constructor

        :param rc: return code
        :type rc: int
        :param stdout: the stout to be displayed
        :type stdout: str
        :param elapsed_time: the time elapsed before the response
        :type elapsed_time: int
        :param command: the command that was executed
        :type command: str

        :returns: an instance of shell.Response
        rtype: shell.Response

        """
        self._rc = rc
        self._stdout = stdout
        self._elapsed_time = None
        self._start_timestamp = elapsed_time
        self._end_timestamp = None
        self._pid = pid
        self.command = command

    @property
    def rc(self):
        """
        Return code

        """
        return self._rc

    @property
    def stdout(self):
        """
        Standard-out

        """
        return self._stdout

    @property
    def start_timestamp(self):
        """
        Command start timestamp

        """
        return self._start_timestamp

    @property
    def end_timestamp(self):
        """
        Command end timestamp

        """
        return self._end_timestamp

    @property
    def elapsed_time(self):
        """
        Command total elapsed time

        """
        return self._elapsed_time

    @property
    def ok(self):
        """
        OK the return code

        """
        return self.rc == 0

    @property
    def pid(self):
        """
        OK the return code

        """
        return self._pid

    def json(self):
        return json.loads(self._stdout)


class ConnectionDetails(object):
    def __init__(self, hostname, username, password=None):
        """
        :type hostname: string
        :type username: string
        :type password: string
        """
        self.hostname = hostname
        self.username = username
        self.password = password

    def __str__(self):
        return "ConnectionDetails({}, {}, {})".format(self.hostname, self.username, self.password)

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return isinstance(other, ConnectionDetails) and (other.hostname, other.username, other.password) == (self.hostname, self.username, self.password)


def local_timeout_killer(proc):
    """
    Callback function used to kill local command execution

    :param proc: Suprocess object which interacts with the shell
    :type proc: subprocess.Popen

    :returns: void

    """

    log.logger.debug("Local command execution has timed out; process will be terminated")

    if proc.poll() is None:
        proc.kill()

    proc.returncode = COMMAND_TIMEOUT_RC


def remote_timeout_killer(connection):
    """
    Callback function used to kill remote command execution

    :type connection: paramiko.Client
    :param connection: Connection whose command execution is to be terminated

    :returns: void

    """

    connection.timed_out = True
    log.logger.debug("Remote command exeuction has timed out; connection will be closed [connection ID {0}]".format(connection.id))
    connection.close()


# Function to ensure that our ConnectionPoolManager is used as a singleton
def get_connection_mgr():
    """
    Function to ensure that our ConnectionPoolManager is used as a singleton

    :returns: the singleton shell.ConnectionPoolManager instance
    :rtype: shell.ConnectionPoolManager

    """
    global connection_mgr

    if connection_mgr is None:
        connection_mgr = ConnectionPoolManager()

    return connection_mgr


def delete_connection_mgr():
    global connection_mgr

    if connection_mgr is not None:
        connection_mgr = None


# Convenience functions to shield consumers from the executors and underlying data structures
def run_local_cmd(cmd):
    """
    Executes a command on the local host

    :param cmd: Command to be executed
    :type cmd: shell.Command or string

    :returns: a shell.Response instance
    :rtype: shell.Response

    """
    if isinstance(cmd, basestring):
        cmd = Command(cmd)
    return LocalExecutor(cmd).execute()


def run_remote_cmd(cmd, host, user, password=None, new_connection=False, ping_host=False, keep_connection_open=False, **kwargs):
    """

    Executes a command on a remote host using an ssh connection

    :param cmd: shell.Command instance containing command to be executed
    :type cmd: Command
    :param host: IP address or hostname of the remote host on which the command is to be executed
    :type host: str
    :param user: Username of the account to use for the SSH connection
    :type user: str
    :param password: Password for the aforementioned user account (optional; not required for public key based connections)
    :type password: str
    :param new_connection: True if you want to establish a new ssh connection by default else False
    :type new_connection: bool
    :param ping_host: True if you want to check if the provided host is reachable else False
    :type ping_host: bool
    :param keep_connection_open: True if you want the connection to the host to remain open after running the command else False
    :type keep_connection_open: bool
    :param kwargs: dictionary of keyword arguments that can be passed to the function
    :type kwargs: dict

    :return: a shell.Response instance with rc=5 if host is not pingable and check was performed else rc=0
    :rtype: Response
    """

    ssh_identity_file = None
    if password == "netsim":
        keep_connection_open = True

    # Needs to be looked into more as to why we don't always ping the host before executing the command,
    # or else allow the connection manager to report the errors (host might go down after the ping and before the
    # command is issued) when it cant issue the command and don't ping at all
    if ping_host and not is_host_pingable(host):
        return Response(rc=5, stdout="Error: Unable to reach host, please ensure the host: {0} is available.".format(host))

    # We need to have identified the deployment at a previous point and maybe pass in a parameter declaring cloud or
    # physical. This module shell should'nt be importing the config module as this is the lowest level module we have
    # and the config module already imports shell so circular dependencies come into play and this is bad.
    if config.is_a_cloud_deployment():
        ssh_identity_file = cache.CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_WL_VM

    connection = get_connection_mgr().get_connection(
        host, user, password, new_connection=new_connection, ssh_identity_file=ssh_identity_file)

    try:
        response = RemoteExecutor(cmd, connection, **kwargs).execute()
    finally:
        connection_mgr.return_connection(host, connection, keep_connection_open=keep_connection_open)

    return response


def run_remote_cmd_with_ms_proxy(cmd, host, username, password=None, ssh_identity_file=None, new_connection=False, ms_proxy=True, **kwargs):
    use_proxy = ms_proxy and not cache.is_host_ms()
    if cache.is_emp():
        use_proxy = True
    connection = get_connection_mgr().get_connection(
        host, user=username, password=password,
        ssh_identity_file=ssh_identity_file, ms_proxy=use_proxy, new_connection=new_connection)
    if connection is None:
        raise RuntimeError(
            "Unable to obtain a connection from the connection pool for remote host {0}".format(host))
    try:
        if isinstance(cmd, basestring):
            cmd = Command(cmd)
        response = RemoteExecutor(cmd, connection, **kwargs).execute()
    finally:
        connection_mgr.return_connection(host, connection)
    return response


def run_cmd_on_vm(cmd, vm_host, user="cloud-user", password=None, ssh_identity_file=DEFAULT_VM_SSH_KEYPATH, new_connection=False, ms_proxy=True, **kwargs):
    """
    Executes a command on a remote host using ssh

    :param cmd: shell.Command instance containing command to be executed
    :type cmd: Command
    :param vm_host: IP address or hostname of the vm on which the command is to be executed
    :type vm_host: str
    :param user: Username of the account to use for the SSH connection
    :type user: str
    :param password: Password for the aforementioned user account (optional; not required for public key based connections)
    :type password: str
    :param ssh_identity_file: location of the ssh identity file
    :type ssh_identity_file: str
    :param new_connection: True if you want to establish a new ssh connection by default else False
    :type new_connection: bool
    :param ms_proxy: true if you want to use a proxy else false
    :type ms_proxy: bool
    :param kwargs: dictionary of keyword arguments that can be passed to the function
    :type kwargs: dict

    :return: a shell.response object containing the results of issuing the command
    :rtype: Response
    """

    # ALTERNATIVE: run_local_cmd('ssh -o "StrictHostKeyChecking no" -o UserKnownHostsFile=/dev/null -o "ProxyCommand ssh -x -a -q root@{0} nc %h 22" -i {1} {2}@{3} {4}'.format(cache.get_ms_host(), ssh_identity_file, user, vm_host, cmd))
    if config.is_a_cloud_deployment():
        cache.copy_cloud_user_ssh_private_key_file_to_emp()
        ssh_identity_file = cache.CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_WL_VM
    return run_remote_cmd_with_ms_proxy(
        cmd, vm_host, user, password=password, ssh_identity_file=ssh_identity_file, new_connection=new_connection, ms_proxy=ms_proxy, **kwargs)


def run_cmd_on_node(cmd, host, username=None, password=None, ssh_identity_file=None, new_connection=False, **kwargs):
    if username is None:
        username, password = config.load_credentials_from_props("litp_username", "litp_password")
    return run_remote_cmd_with_ms_proxy(
        cmd, host, username, password, ssh_identity_file=ssh_identity_file, new_connection=new_connection, **kwargs)


def run_cmd_on_ms(cmd, **kwargs):
    """
    Runs command on MS. If running on MS it will run command locally
    :param cmd: shell.Command to be executed
    """
    hostname = cache.get_ms_host()
    if hostname == 'localhost' or not hostname:
        return run_local_cmd(cmd)
    ms_username, ms_password = cache.get_ms_credentials()
    if isinstance(cmd, basestring):
        cmd = Command(cmd)
    return run_remote_cmd(cmd, hostname, ms_username, ms_password, ping_host=True, **kwargs)


def run_cmd_on_vnf(cmd, **kwargs):
    """
    Runs command on VNFLAF. If running on MS it will run command locally

    :type cmd: `shell.Command`
    :param cmd: shell.Command to be executed

    :raises: ValueError

    :rtype: `shell.Response`
    :return: Shell response object
    """
    hostname = cache.get_vnf_laf()
    if not hostname:
        return run_cmd_on_ms(cmd, **kwargs)
    vnflaf_username, vnflaf_password = cache.get_vnf_laf_credentials()
    if isinstance(cmd, basestring):
        cmd = Command(cmd)
    return run_remote_cmd(cmd, hostname, vnflaf_username, vnflaf_password, ping_host=True, **kwargs)


def are_ssh_credentials_valid(host, user, password=None, ssh_identity_file=None, ms_proxy=False, allow_agent=True, look_for_keys=True):
    """
    Checks whether the specified username and password are valid

    :param host: str, Hostname or IP address of the host to check
    :param user: str, SSH username used to log in
    :param password: str, SSH password used to log in
    :param ssh_identity_file: str, the filename of a private key to try for authentication
    :param ms_proxy: bool, True to create an open socket or socket-like object (such as a `.Channel`) to use for communication to the target host else False
    :param allow_agent: bool, set to False to disable connecting to the SSH agent
    :param look_for_keys: bool, set to False to disable searching for discoverable private key files in ``~/.ssh/``

    :return: bool, True if credentials are valid else False
    """

    result = False

    try:
        get_connection_mgr()._establish_connection(host, user, password, verbose=False, ssh_identity_file=ssh_identity_file, ms_proxy=ms_proxy, allow_agent=allow_agent, look_for_keys=look_for_keys)
        result = True
        log.logger.debug("Established valid SSH credentials for {username}@{hostname}".format(username=user, hostname=host))
    except Exception as e:
        log.logger.debug("Exception in shell.are_ssh_credentials_valid: {0}".format(str(e)))

    return result


def copy_ssh_key_to_server(host, user, password, keyfile="~/.ssh/id_rsa.pub", ssh_identity_file=None, ms_proxy=False):
    """
    Copies the user's public key and the host's key to the specified remote host


    :param host: Hostname or IP address of the host to which the keys should be copied
    :type host: string
    :param user: SSH username to use to log in to the remote host
    :type user: string
    :param password: Password for the SSH user account specified in L{user}
    :type password: string
    :param keyfile: Absolute path to the keyfile to copy to the remote host (defaults to '~/.ssh/id_rsa.pub') [optional]
    :type keyfile: string

    :returns: void

    """

    if _check_passwordless_access(host, "netsim"):
        return

    # At this point we don't have passwordless access, so if there is any host key delete it
    run_local_cmd(Command("ssh-keygen -R {0}".format(host)))
    run_local_cmd(Command("ssh-keyscan -H {0}".format(host)))

    # Check that the credentials are correct
    if not are_ssh_credentials_valid(host, user, password):
        raise RuntimeError("Invalid username/password combo for host {0}" .format(host))

    # Make sure that the keyfile exists
    keyfile = os.path.expanduser(keyfile)
    if not filesystem.does_file_exist(keyfile):
        run_local_cmd(Command('ssh-keygen -b 2048 -t rsa -f ~/.ssh/id_rsa -q -N ""'))
        if not filesystem.does_file_exist(keyfile):
            raise RuntimeError("Key file {0} doesn't exist; no key file to copy to remote host".format(keyfile))

    # Establish a connection to the remote host
    connection = get_connection_mgr().get_connection(host, user, password, ssh_identity_file=ssh_identity_file)
    if connection is None:
        raise RuntimeError("Unable to establish connection to remote host {0} as user {1}".format(host, user))

    try:
        # Read in the key
        key = open(keyfile).read()

        # Make a list of lists of the commands we want to run and the error messages to raise if they don't run correctly
        cmd_list = []
        cmd_list.append(["mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys", "Could not verify that ~/.ssh/authorized_keys exists on {0}".format(host)])
        cmd_list.append(["echo \"{0}\" >> ~/.ssh/authorized_keys".format(key), "Could not add public key to ~/.ssh/authorized_keys on {0}".format(host)])
        cmd_list.append(["sort < ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp", "Could not sort keys in file ~/.ssh/authorized_keys on {0}".format(host)])
        cmd_list.append(["uniq < ~/.ssh/authorized_keys.tmp > ~/.ssh/authorized_keys", "Could not remove duplicates in file ~/.ssh/authorized_keys on {0}".format(host)])
        cmd_list.append(["chmod 0644 ~/.ssh/authorized_keys", "Could not chmod file ~/.ssh/authorized_keys to 0644 on {0}".format(host)])
        cmd_list.append(["rm -f ~/.ssh/authorized_keys.tmp", "Could not remove temporary key file ~/.ssh/authorized_keys.tmp on {0}".format(host)])

        # Run each of the commands to add the key and remove duplicates
        with mutexer.mutex("remove_duplicated_ssh_keys"):
            for (cmd, error_msg) in cmd_list:
                response = RemoteExecutor(Command(cmd), connection).execute()
                if not response.ok:
                    raise RuntimeError(error_msg)

        log.logger.debug("Successfully added public key to authorized_keys file on host {0}".format(host))

        # Now add the remote hosts host key to our known_hosts file
        # These commands are run as a best effort; if they don't succeed, it's OK because we've configured our SSH client to accept unknown host keys
        run_local_cmd(Command("ssh-keygen -R {0}".format(host)))
        run_local_cmd(Command("ssh-keyscan -H {0}".format(host)))
        log.logger.debug("Successfully added remote host's ({0}) host key to our known_hosts file".format(host))

        # Verify that we can establish a session without the password
        connection = get_connection_mgr()._establish_connection(host, user, ssh_identity_file=ssh_identity_file, ms_proxy=ms_proxy)
        log.logger.debug("Successfully verified that we can establish SSH session to host {0} with public key authentication".format(host))
    finally:
        # Return the connection to the pool
        connection_mgr.return_connection(host, connection)


def upload_file(local_path, remote_path, host, user, password=None, file_permission=None):
    """
    Copies a local file to the specified path on the remote host

    :param local_path: Absolute path to the local file to be copied to the remote host
    :type local_path: string
    :param remote_path: Absolute path on the remote host to which the file should be copied
    :type remote_path: string
    :param host: Hostname or IP address of the host to which the keys should be copied
    :type host: string
    :param user: SSH username to use to log in to the remote host
    :type user: string
    :param password: Password for the SSH user account specified in L{user}
    :type password: string
    :param file_permission: Permission to give the copied file if specified. Of the form 755, 644 etc.
    :type file_permission: int

    :returns: void

    """

    # Create remote dir if it doesnt exist
    base_dir = os.path.dirname(remote_path)

    # Get a connection from the pool
    connection = get_connection_mgr().get_connection(host, user, password)

    if not hasattr(connection, "sftp_client"):
        connection.sftp_client = connection.open_sftp()

    try:
        connection.sftp_client.chdir(base_dir)  # Test if remote_path exists
    except IOError:
        connection.sftp_client.mkdir(base_dir)

    try:
        connection.sftp_client.put(local_path, remote_path, confirm=True)
        if file_permission:
            connection.sftp_client.chmod(path=remote_path, mode=file_permission)
    finally:
        connection_mgr.return_connection(host, connection)


def upload_file_to_ms(local_path, remote_path, file_permission=None):
    """
    :param local_path: path to the local file
    :type local_path: str
    :param remote_path: path to the remote file
    :type remote_path: str
    :param file_permission: Permission to give the copied file if specified. Of the form 755, 644 etc.
    :type file_permission: int
    :returns: None
    :raises: RuntimeError, IOError
    """
    if cache.is_host_ms():
        raise RuntimeError('Already on MS, cannot upload')
    ms_username, ms_password = cache.get_ms_credentials()
    return upload_file(
        local_path, remote_path, cache.get_ms_host(), ms_username, password=ms_password, file_permission=file_permission)


def download_file(remote_path, local_path, host, user, password=None):
    """
    Copies a file from the specified path on the remote host to the local host

    :param remote_path: Absolute path on the remote host to which the file should be copied
    :type remote_path: string
    :param local_path: Absolute path to the local file to be copied to the remote host
    :type local_path: string
    :param host: Hostname or IP address of the host to which the keys should be copied
    :type host: string
    :param user: SSH username to use to log in to the remote host
    :type user: string
    :param password: Password for the SSH user account specified in L{user}
    :type password: string

    :returns: void

    """

    # Get a connection from the pool
    connection = get_connection_mgr().get_connection(host, user, password)

    # Check to see if an SFTP client has already been initialized for this connection; if not, initialize one
    if not hasattr(connection, "sftp_client"):
        connection.sftp_client = connection.open_sftp()
    try:
        connection.sftp_client.get(remote_path, local_path)
    finally:
        # Return the connection to the pool
        connection_mgr.return_connection(host, connection)


def download_directory_tree(remote_path, local_path, host, user, password=None):
    """
    Copies files from the specified directory on the remote host to the local host

    :param remote_path: Absolute path on the remote host to which the file should be copied
    :type remote_path: string
    :param local_path: Absolute path to the local file to be copied to the remote host
    :type local_path: string
    :param host: Hostname or IP address of the host to which the keys should be copied
    :type host: string
    :param user: SSH username to use to log in to the remote host
    :type user: string
    :param password: Password for the SSH user account specified in L{user}
    :type password: string
    :returns: void
    """
    # Get a connection from the pool
    connection = get_connection_mgr().get_connection(host, user, password, allow_agent=False, look_for_keys=False)

    # Check to see if an SFTP client has already been initialized for this connection; if not, initialize one
    if not hasattr(connection, "sftp_client"):
        connection.sftp_client = connection.open_sftp()
    try:
        if os.path.basename(remote_path) in connection.sftp_client.listdir(os.path.dirname(remote_path)):
            parent_dir_index = len(remote_path.split(os.sep)) - 1
            directory_list, file_list = _retrieve_directories_and_files_from_remote(connection, remote_path, set(), set())

            for directory in directory_list:
                directory_relative_path = os.sep.join(directory.split(os.sep)[parent_dir_index:])
                filesystem.create_dir(os.path.join(local_path, directory_relative_path))

            for filename in file_list:
                parent_directory_relative_path = os.sep.join(filename.split(os.sep)[parent_dir_index:-1])
                filesystem.create_dir(os.path.join(local_path, parent_directory_relative_path))

                file_relative_path = os.sep.join(filename.split(os.sep)[parent_dir_index:])
                connection.sftp_client.get(filename, os.path.join(local_path, file_relative_path))
        else:
            raise IOError("File does not exist: {}".format(remote_path))
    finally:
        # Return the connection to the pool
        connection_mgr.return_connection(host, connection)


def _retrieve_directories_and_files_from_remote(connection, remote_path, directories, files):
    """
    B{Retrieves the directories and files on the source system under remote_path}

    :type connection: paramiko.Client
    :param connection: Connection to source system via SFTP
    :type remote_path: string
    :param remote_path: Path to remote directory on source system
    :type directories: set(string)
    :param directories: Directories under remote directory path
    :type files: set(string)
    :param files: Files under remote directory path
    :return: The directories under remote directory path
    :rtype: set(string)
    """
    for file_attributes in connection.sftp_client.listdir_attr(remote_path):
        if S_ISDIR(file_attributes.st_mode):
            directories.add(os.path.join(remote_path, file_attributes.filename))
            _retrieve_directories_and_files_from_remote(connection, os.path.join(remote_path, file_attributes.filename), directories, files)
        else:
            files.add(os.path.join(remote_path, file_attributes.filename))

    return directories, files


def sftp_path_exists(remote_path, host, user, password=None):
    """
    :type remote_path: string
    :type host: string
    :type user: string
    :type password: string
    :rtype: bool
    """
    connection = get_connection_mgr().get_connection(host, user, password)
    if not hasattr(connection, "sftp_client"):
        connection.sftp_client = connection.open_sftp()

    try:
        connection.sftp_client.stat(remote_path)
    except IOError as e:
        if e.errno == errno.ENOENT:
            return False
        raise
    else:
        return True


def _check_passwordless_access(remote_ms, user='root'):
    """
    Checks if the client has passwordless access to the remote MS

    :param remote_ms: The IP of the remote MS
    :type remote_ms: string
    :param user: username to check
    :type user: string

    :returns: True if the client has passwordless access to the remote MS, False if not.
    :rtype: boolean

    """
    ssh_cmd = "/usr/bin/ssh -o PreferredAuthentications=publickey -o ConnectTimeout=5 -o StrictHostKeyChecking=no {0}@{1} ls".format(user, remote_ms)
    cmd = Command(ssh_cmd)
    cmd.allow_retries = False

    res = LocalExecutor(cmd).execute()
    return res.ok


def validate_remote_XML_file(file_path, ip, username, password=None):
    """
    Checks if the exported file created by a particular cm export command is valid

    :type file_path: string
    :param file_path: The full path to the file
    :type username: string
    :param username: username for user to be used to make the request
    :type password: string
    :param password: password
    :rtype: boolean
    :return: If the exported file was valid or not
    """

    validate_xml_file_cmd = "xmllint --stream {filename}".format(filename=file_path)
    validate_cmd = Command(validate_xml_file_cmd, timeout=900)
    log.logger.debug('Trying to validate xml file "%s" on host "%s"' % (file_path, ip))
    response = run_remote_cmd(validate_cmd, ip, username, password)
    if response.rc != 0:
        raise ShellCommandReturnedNonZero('Xml file validation failed.', response=validate_cmd)
    log.logger.debug(
        "Xml file '%s' validated successfully on host '%s'" % (file_path, ip))


def change_local_file_permisions(permissions, file_path):
    """
    Change file permissions
    :param permissions:

    :raises: ShellCommandReturnedNonZero
    :returns: None
    """
    cmd_response = run_cmd_on_ms(Command('chmod {0} {1}'.format(permissions, file_path)))
    if not cmd_response.rc == 0:
        raise ShellCommandReturnedNonZero('Changing permissions on the file: {0} failed. '
                                          'OUTPUT: {1}'.format(file_path, cmd_response.stdout), cmd_response)


def change_deployment_file_permissions(permissions, file_path, host):
    """
    Change file permissions on deployment

    :type permissions: str
    :param permissions: Permissions to apply to file
    :type file_path: str
    :param file_path: Path way to the file to be alter permissions
    :type host: str
    :param host: name of the remote host to execute change upon

    :raises: ShellCommandReturnedNonZero
    :returns: void
    """
    cmd_response = run_cmd_on_vm(Command('sudo chmod {0} {1}'.format(permissions, file_path)), vm_host=host)
    if not cmd_response.rc == 0:
        raise ShellCommandReturnedNonZero('Changing permissions on the file: {0} failed. '
                                          'OUTPUT: {1}'.format(file_path, cmd_response.stdout), cmd_response)
