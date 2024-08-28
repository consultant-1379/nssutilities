import datetime
import signal
import sys
import time

import ctypes
import multiprocessing
import os
import threading
import inspect
import subprocess
import process
import log
import persistence
import filesystem
import exception
import cache
import timestamp

# List of all UtilitiesThread instances we initialize over the course of the run
initialized_utilities_threads = []


class UtilitiesWorkerEntry(object):

    def __init__(self, function, arg_list):
        """
        UtilitiesWorkerEntry constructor

        :param function: The function reference object
        :type function: object
        :param arg_list: List of arguments to pass to the function reference
        :type arg_list: list
        """

        self.function = function
        self.arg_list = arg_list
        self.result = None
        self.finished = False


class AbstractUtilitiesDaemon(object):

    def __init__(self, identifier):
        """
        AbstractUtilitiesDaemon constructor

        :param identifier: Unique identifier for this process (must be unique to prevent PID file collision)
        :type identifier: string
        """

        self.id = identifier
        self.proc = None
        self.pid = None
        self.name = ""
        self.desc = ""
        self.close_all_fds = False
        self.cmd = []
        self.piddir = "/var/tmp/nssutils/daemon"
        self.pidfile = os.path.abspath(os.path.realpath(os.path.join(self.piddir, "%s.pid" % identifier)))

        self.base_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

        if not os.path.isdir(self.piddir):
            os.makedirs(self.piddir)
            filesystem.change_owner(self.piddir, group_name="wheel")
            os.chmod(self.piddir, 0777)

    def _raise_if_running(self):
        # See if a daemon with this identifier is already running
        pid = self.get_pid()
        if pid is not None:
            raise RuntimeError("PID file %s already exists; a daemon with this identifier appears to be running" % self.pidfile)

    def start(self):
        """
        Starts this daemon process
        """

        self._raise_if_running()

        if log.logger is not None:
            log.logger.debug("  Starting {0}".format(self.desc))
            log.logger.debug("  Executing daemon command {0}".format(str(self.cmd)))

        # Start the daemon
        if self.close_all_fds:
            self.proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.base_dir, shell=False, close_fds=True, preexec_fn=os.setpgrp)
            self.proc.stdout.close()
        else:
            self.proc = subprocess.Popen(self.cmd, stdout=1, stderr=subprocess.STDOUT, cwd=self.base_dir, shell=False, close_fds=True, preexec_fn=os.setpgrp)

        # Write pidfile
        self.write_pid_file()

    def write_pid_file(self):
        """
        Writes the PID file for this daemon process
        """
        self.pid = self.proc.pid
        with open(self.pidfile, 'w+') as f:
            f.write("%s\n" % self.pid)

    def delete_pid_file(self):
        """
        Deletes the PID file for this daemon process
        """
        os.remove(self.pidfile)

    def get_pid(self):
        """
        Gets the PID from the PID file for this daemon process

        :return: pid
        :rtype: int

        """

        if self.pid is None:
            try:
                with open(self.pidfile, 'r') as file_handle:
                    self.pid = int(file_handle.read().strip())
            except (ValueError, IOError):
                self.pid = None

        return self.pid

    def stop(self):
        """
        Stops this daemon process
        """

        # Get the pid from the pidfile
        pid = self.get_pid()
        if not pid:
            log.logger.error("PID file {0} does not exist; the daemon is not running...".format(self.pidfile))
            return

        # Kill the daemon process
        process_is_dead = False
        if process.is_pid_running(pid):
            try:
                # Loop and check to see if the process has died
                x = -1
                while x < 15:
                    x = x + 1

                    if process.is_pid_running(pid):
                        # If the process hasn't died gracefully after a half a second, move to TERM and eventually KILL signals
                        if x > 12:
                            process.kill_pid(pid, signal.SIGKILL)
                        elif x > 0 and x % 2 == 0:
                            process.kill_pid(pid, signal.SIGTERM)
                        else:
                            process.kill_pid(pid, signal.SIGINT)

                        time.sleep(.1)
                    else:
                        process_is_dead = True
                        break
            except:
                exception.process_exception("Could not stop daemon process [{0}]".format(self.name))

        else:
            process_is_dead = True

        if process_is_dead:
            log.logger.info(str("  Successfully terminated %s [%s]" % (self.name, self.pid)))

        self.delete_pid_file()

    def restart(self):
        """
        Restarts this daemon process
        """

        self.stop()
        self.start()

    @property
    def running(self):
        """
        Checks if daemon is running on the background
        """

        return self.get_pid() is not None and process.is_pid_running(self.get_pid())


class UtilitiesDaemon(AbstractUtilitiesDaemon):
    counter = 1

    def __init__(self, identifier, target, args=None, properties_files=None, log_identifier=None,
                 scheduler=False):
        """
        UtilitiesDaemon constructor

        :param identifier: Unique identifier for this process (must be unique to prevent PID file collision)
        :type identifier: string
        :param target: Reference to the function to be executed by the new process
        :type target: function reference
        :param args: Arguments to be passed to the function when it is invoked
        :type args: list
        :param properties_files: Config files to load by .daemon.py
        :type properties_files: list
        :param log_identifier: log file name
        :type log_identifier: string
        :param scheduler: bool to indicate if this is a scheduler daemon
        :type scheduler: bool
        :raises ValueError: if target is none or target is not callable
        """

        properties_files = properties_files or []

        AbstractUtilitiesDaemon.__init__(self, identifier)

        args = args or []

        if target is None or not callable(target):
            raise ValueError("Parameter target must be a valid function reference")

        self.name = "UtilitiesDaemon-%s" % UtilitiesDaemon.counter
        UtilitiesDaemon.counter = UtilitiesDaemon.counter + 1
        self.desc = "%s [%s]" % (self.name, identifier)

        persistence.set(str('%s_pickled' % identifier), [target, args], 30 * 60)
        log.logger.debug("Created pickled dump object {0}".format(identifier))

        # Build the command we will execute
        daemon_path = os.path.join(os.path.dirname(sys.executable), "daemon")
        self.cmd = [daemon_path, identifier]
        if log_identifier is not None:
            self.cmd.append(log_identifier.lower())
        if scheduler:
            self.cmd.append('--scheduler')


class UtilitiesExternalDaemon(AbstractUtilitiesDaemon):
    counter = 1

    def __init__(self, identifier, cmd):
        """
        UtilitiesExternalDaemon constructor

        NOTE: Parameter 'cmd' must be supplied as a list of strings where the first entry is the binary and all subsequent entries are commnad line parguments

        :param identifier: Unique identifier for this process (must be unique to prevent PID file collision)
        :type identifier: string
        :param cmd: Full shell command to run
        :type cmd: string
        :raises ValueError: if command is none or command length is less than 1
        """

        AbstractUtilitiesDaemon.__init__(self, identifier)

        if cmd is None or len(cmd) < 1:
            raise ValueError("Parameter cmd must be a valid string and cannot be NoneType")

        self.cmd = cmd
        self.name = "UtilitiesExternalDaemon-%s" % UtilitiesExternalDaemon.counter
        UtilitiesExternalDaemon.counter = UtilitiesExternalDaemon.counter + 1

        if len(cmd) < 60:
            self.desc = "%s [%s]" % (self.name, cmd)
        else:
            self.desc = "%s [%s]" % (self.name, self.cmd[0])


class UtilitiesProcess(multiprocessing.Process):

    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None):
        """
        UtilitiesProcess constructor

        :param group: Process group in which new process is to be created (not normally specified).
        :type group: str
        :param target: The function/method to be invoked by the new process
        :type target: function reference
        :param name: The name to be given to the new process
        :type name: str
        :param args: Arguments to be passed to the function/method when it is invoked
        :type args: list
        :param kwargs: Diction of keyword arguments to be passed to the function/method when it is invoked
        :type kwargs: dict
        """

        kwargs = kwargs or {}

        multiprocessing.Process.__init__(self, group=group, target=target, name=name, args=args, kwargs=kwargs)
        self.daemon = False
        self.func_ref = None
        self.target = target
        self.desc = None

    def start(self):
        """
        Starts the Utilities daemon process
        """

        if self.func_ref is not None:
            self.desc = "{0} {1}()".format(self.name, self.func_ref.__name__)
        else:
            self.desc = "{0} {1}()".format(self.name, self.target.__name__)

        if log.logger is not None:
            log.logger.debug("  Starting " + self.desc)

        super(UtilitiesProcess, self).start()

    def run(self):
        """
        Runs the Utilities daemon process
        """

        try:
            super(UtilitiesProcess, self).run()
        except:
            exception.process_exception("Exception raised by process {0}".format(self.desc))

    def has_raised_exception(self):
        """
        Returns whether an exception has been raised.

        :returns: whether an exception has been raised
        :rtype: boolean
        """

        return False


class UtilitiesThread(threading.Thread):

    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None):
        """
        UtilitiesThread constructor

        :param group: Process group in which new thread is to be created (not normally specified)
        :type group: string
        :param target: The function/method to be invoked by the new thread
        :type target: function reference
        :param name: The name to be given to the new thread
        :type name: string
        :param args: Arguments to be passed to the function/method when it is invoked
        :type args: list
        :param kwargs: Diction of keyword arguments to be passed to the function/method when it is invoked
        :type kwargs: dict
        """

        kwargs = kwargs or {}

        global initialized_utilities_threads

        threading.Thread.__init__(self, group=group, target=target, name=name, args=args, kwargs=kwargs)
        self.exception_raised = False
        self.exception_msg = None
        self.func_ref = None
        self.target = target
        self.desc = None
        self._thread_id = None

        initialized_utilities_threads.append(self)

    def start(self):
        """
        Starts the Utilities daemon process
        """

        self.daemon = False

        if self.func_ref is not None:
            self.desc = "{0} {1}()".format(self.name, self.func_ref.__name__)
        else:
            self.desc = "{0} {1}()".format(self.name, self.target.__name__)

        if log.logger is not None:
            log.logger.debug("  Starting " + self.desc)

        super(UtilitiesThread, self).start()

    def run(self):
        """
        Runs the Utilities daemon process
        """

        try:
            super(UtilitiesThread, self).run()
        except Exception as e:
            exception.process_exception("Exception raised by thread {0}".format(self.desc))
            self.exception_raised = True
            self.exception_msg = e.args[0]

    def has_raised_exception(self):
        """
        Returns whether the UtilitiesThread has raised an exception or not

        :return: whether an exception is raised or not
        :rtype: boolean
        """

        return self.exception_raised

    def get_exception_msg(self):
        """
        Gets and returns the exception msg

        :returns: the exception msg
        :rtype: string
        """

        return self.exception_msg

    def _get_my_tid(self):
        """
        determines this (self's) thread id
        """

        if not self.isAlive():
            raise threading.ThreadError("the thread is not active")

        # do we have it cached?
        if self._thread_id:
            return self._thread_id

        # no, look for it in the _active dict
        for tid, tobj in threading._active.items():
            if tobj is self:
                self._thread_id = tid
                return tid

        raise AssertionError("could not determine the thread's id")

    def raise_exc(self, exctype):
        """raises the given exception type in the context of this thread"""
        _async_raise(self._get_my_tid(), exctype)

    def terminate(self):
        """raises SystemExit in the context of the given thread, which should
        cause the thread to exit silently (unless caught)"""
        self.raise_exc(SystemExit)


# Solution for python thread killing taken from stack overflow
# http://stackoverflow.com/questions/323972/is-there-any-way-to-kill-a-thread-in-python
def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    if not inspect.isclass(exctype):
        log.logger.debug("Only types can be raised (not instances)")
        raise TypeError("Only types can be raised (not instances)")
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(exctype))
    if res == 0:
        log.logger.debug("Invalid thread id: {0}".format(tid))
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), 0)
        log.logger.debug("Failure of SystemExit for thread: {0}".format(tid))
        raise SystemError("PyThreadState_SetAsyncExc failed")

    log.logger.debug("Successfully initialised SystemExit of thread: {0}".format(tid))


def terminate_threads(wait_for_threads_to_finish=False):
    """
    Sets thread termination signal and waits for all threads to finish

    :param wait_for_threads_to_finish: Wait for running threads to be joined before returning
    :type wait_for_threads_to_finish: boolean
    """

    log.log_entry()

    if log.logger is not None:
        log.logger.debug("Notifying all threads that they need to terminate as quickly as possible (this can take a bit of time)...")

    # Set poison pill so that threads know to exit as soon as possible
    cache.set("should-workers-exit", True)
    join_interval = .01

    # Get a list of all of the threads running in this process
    if log.logger is not None:
        log.logger.debug("Attempting to join {0} running threads...".format(len(initialized_utilities_threads)))

    # Try to kill any and all threads that the threading module knows about
    if wait_for_threads_to_finish:
        if log.logger is not None:
            log.logger.debug("Waiting for all threads to finish and join...")

        wait_for_tasks_to_finish(initialized_utilities_threads)
    else:
        if log.logger is not None:
            log.logger.debug("Making a best-effort attempt to join all running threads...")

        for t in initialized_utilities_threads:
            if t.is_alive() and t != threading.current_thread():
                t.join(join_interval)

    # Now iterate again and see if we have any threads we're waiting on
    live_thread_counter = 0
    for t in threading.enumerate():
        if t.is_alive() and t != threading.current_thread():
            if log.logger is not None:
                log.logger.debug("  Unable to join {0} on first join attempt...".format(t.name))
            live_thread_counter = live_thread_counter + 1

    if live_thread_counter > 0:
        if log.logger is not None:
            log.logger.debug("Unable to join {0} threads...".format(live_thread_counter))
    else:
        if log.logger is not None:
            log.logger.debug("All threads joined successfully on first attempt")
    cache.set("should-workers-exit", False)


def should_workers_exit():
    """
    Function to be invoked by workers to see if they need to do a premature exit

    :returns: whether the worker should exit or not
    :rtype: boolean

    """

    should_exit = cache.get("should-workers-exit")

    if should_exit is None:
        should_exit = False

    return should_exit


def get_num_tasks_running(tasks_list):
    """
    Returns the number of tasks in the tasks_list that are still running

    :param tasks_list: list of processes or threads to monitor and eventually terminate
    :type tasks_list: list of multiprocessing.Process objects or threading.Thread objects

    :returns: number of tasks still running
    :rtype: int

    """

    num_running = 0

    for task in tasks_list:
        if task.is_alive() and not task.has_raised_exception():
            num_running = num_running + 1

    return num_running


def wait_for_tasks_to_finish(tasks_list, timeout=None):
    """
    Waits for all of the previously registered tasks to finish, either a list of processes or a list of threads

    :param: tasks_list: list of processes or threads to monitor and eventually terminate
    :type: tasks_list: list of multiprocessing.Process objects or threading.Thread objects
    :param: timeout: Maximum time to wait (in seconds) to collect all tasks
    :type: timeout: int
    """

    log.log_entry()
    # If we don't have anything to wait on, return
    if tasks_list is None or len(tasks_list) < 1:
        return

    log.logger.debug("Waiting for {0} tasks to finish...".format(len(tasks_list)))

    # Set a limit for how long we're willing to wait for the tasks to join
    if timeout is None:
        timeout = 360

    # Set a time limit so we don't get stuck if something deadlocks
    start_time = timestamp.get_current_time()
    wait_time = datetime.timedelta(seconds=timeout)
    elapsed_time = timestamp.get_current_time() - start_time

    # Wait for either: (1) all threads to finish or raise an exception or (2) the timeout expires
    unjoined_tasks = tasks_list
    while elapsed_time < wait_time:
        # Join any tasks that have finished or raised exceptions
        unjoined_tasks = join_tasks(unjoined_tasks)

        # Check to see if everyone has finished
        if len(unjoined_tasks) == 0:
            break

        # Wait a bit before the next loop iteration
        time.sleep(.1)
        elapsed_time = timestamp.get_current_time() - start_time

    # Report if there are any workers that couldn't be joined
    if len(unjoined_tasks) == 0:
        log.logger.debug("All {0} tasks have finished and been joined".format(len(tasks_list)))
    else:
        log.logger.debug("{0}/{1} tasks have not finished when finish timeout ran out".format(len(unjoined_tasks),
                                                                                              len(tasks_list)))
        for task in unjoined_tasks:
            log.logger.debug("  Couldn't join task {0} [{1}]".format(task.name, task.desc))
            try:
                task.terminate()
            except Exception as e:
                log.logger.debug("  Couldn't terminate task {0} [{1}]".format(task.name, str(e)))


def join_tasks(tasks_list, max_join_time=.2):
    """
    Attempts to join all tasks in the task list

    :param tasks_list: list of UtilitiesProcess or UtilitiesThread instances
    :type tasks_list: list
    :param max_join_time: Maximum time (in seconds) to wait for the join
    :type max_join_time: float
    :returns: list of unfinished tasks
    :rtype: list
    """

    unjoined_tasks = []
    global initialized_utilities_threads

    for task in tasks_list:
        join = False

        # If the worker has raised an exception or is no longer running, join it
        if hasattr(task, "has_raised_exception") and task.has_raised_exception():
            log.logger.debug("  Task {0} has raised an exception".format(task.name))
            log.logger.debug("    {0}".format(task.exception_msg))
            join = True
        elif task.is_alive():
            unjoined_tasks.append(task)
        else:
            log.logger.debug("  Task {0} has finished and been joined".format(task.name))
            join = True

        if join:
            task.join(max_join_time)
            if task in initialized_utilities_threads:
                initialized_utilities_threads.remove(task)

    return unjoined_tasks


def invoke_instance_methods(instance, method_calls):
    """
    Hack to convert profile methods to functions

    :param instance: th instance we want to call bound methods on
    :type instance: instance of some object
    :param method_calls: each tuple will contain at index 0 name of method, index 1 positional args for method, index 2 keyword args for method
    :type method_calls: list of tuples (string, list, dict)
    """

    for name, args, kwargs in method_calls:
        getattr(instance, name)(*args, **kwargs)
