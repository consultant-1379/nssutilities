import os
import time
import signal

# These modules are imported relatively from current python package i.e. lib
# and to avoid circular imports we cannot do from . import ...
import log
import shell
# End circular imports


def is_pid_running(pid):
    """
    B{Checks whether the specified process is running}

    @type pid: string
    @param pid: Process ID to be checked
    @rtype: boolean
    """

    pid = str(pid)

    response = shell.run_local_cmd(shell.Command("ps --no-headers -p %s -o stat" % pid))
    status = response.stdout

    if "D" in status or "R" in status or "S" in status or "T" in status:
        log.logger.debug("Process ID %s is running on the deployment" % pid)
        return True
    else:
        log.logger.debug("Process ID %s is not running on the deployment" % pid)
        return False


def is_pid_running_on_remote_host(pid, host, user, password=None):
    """
    B{Checks whether the specified process is running on the remote host}

    @type pid: string
    @param pid: Process ID to be checked
    @type host: string
    @param host: hostname or IP address
    @type user: string
    @param user: SSH login username
    @type password: string
    @param password: SSH login password [optional]
    @rtype: boolean
    """

    result = False
    status = ""

    cmd = shell.Command("ps --no-headers -p {0} -o stat".format(pid))
    response = shell.run_remote_cmd(cmd, host, user, password)

    if response.stdout is not None and len(response.stdout) > 0:
        status = response.stdout.strip().upper()

    if "D" in status or "R" in status or "S" in status or "T" in status:
        log.logger.debug("Process ID %s is running on host %s" % (pid, host))
        result = True
    else:
        log.logger.debug("Process ID %s is not running on host %s" % (pid, host))

    return result


def kill_pid(pid, sig=None):
    """
    B{Kills a local process with user-specified signal}

    @type pid: string
    @param pid: Process ID to be killed
    @type sig: int
    @param sig: Signal to be sent to the process (defaults to SIGKILL)
    @rtype: boolean
    """

    sig = sig or signal.SIGKILL

    result = False

    os.killpg(os.getpgid(pid), sig)
    time.sleep(.001)

    if not is_pid_running(pid):
        result = True

    return result


def is_pid_running_with_arg(pid, arg):
    """
    B{Checks if pid is running and argument to the process is same as passed in as parameter}

    @type pid: string
    @param pid: Process ID to be killed
    @type arg: str
    @param arg: Argument to check in process arguments
    @rtype: boolean
    """
    result = False
    try:
        response = shell.run_local_cmd('cat /proc/{0}/cmdline'.format(pid))
        # Make sure that pid is running without provided arg
        if response.ok and str(arg) in response.stdout:
            result = True
    except:
        pass

    return result
