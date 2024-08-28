import os
import signal
import multiprocessing

import config
import cache
import multitasking
import log
import persistence
import exception
import mutexer

__main_process_pid = None

CPU_TOOLS_MAP = {
    'node_populator': 4,
}


def global_init(run_type, tool_class, run_name, args=None, simplified_logging=False, execution_timeout=900):
    """
    B{Initializes logging and loads our configuration properties files into memory}

    @type run_type: string
    @param run_type: The type of action being run (tool||service||testcase||*test)
    @type tool_class: string
    @param tool_class: The package of action being run (prod or int)
    @type run_name: string
    @param run_name: The name of the action being run
    @type args: list
    @param args: List of arguments provided for the action
    @type simplified_logging: boolean
    @param simplified_logging: Controls whether simplified logging (in process; debug-only) should be initialized
    @type execution_timeout: int
    @param execution_timeout: Value that sets the maximum execution time in seconds
    @rtype: void
    """

    cache.set("run_type", run_type)
    args = args or []

    # Load our configuration properties
    try:
        config.load_config(tool_class=tool_class)
    except:
        print log.red_text("Could not load configuration properties. The system is in an unexpected state or is not configured correctly.")
        exit(5)

    # Initialize logging
    try:
        if "unit-test" in run_type:
            log.test_log_init()
        elif "func-test" in run_type:
            log.simplified_log_init(run_name, overwrite=True, log_dir=os.path.join(config.get_log_dir(), "test"))
        elif simplified_logging:
            log.simplified_log_init(run_name)
        else:
            log.log_init()
    except Exception as e:
        print log.red_text("Could not initialize logging. The system is in an unexpected state or is not configured correctly: {}".format(e))
        exit(5)

    # If the run type is unit-test, return now
    if "unit-test" in run_type:
        return

    # Check if tool meets the CPU cores requirement on the MS. This is based on our estimation that a minimum of 4 CPU's
    # are required to run a node_populator command
    if run_name in CPU_TOOLS_MAP and multiprocessing.cpu_count() < CPU_TOOLS_MAP[run_name]:
        log.logger.warn('The number of CPU cores on this MS is less than the minimum required cores for this tool. This tool may under-perform or hang as a result')

    log.logger.debug("Starting {0} [{1}] {2}".format(run_name, run_type, args[1:]))
    log.logger.syslog("Starting {0} {1}".format(run_name, args[1:]))

    # Make sure that the general-purpose scratch directory exists
    try:
        temp_dir = config.get_prop("temp_dir")
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
    except:
        exception.process_exception("Unable to confirm that temp directory {0} exists".format(temp_dir))
        log.logger.error("Could not verify that the general-purpose scratch directory exists. The system is in an unexpected state or is not configured correctly.")
        exit(5)

    # Sets the execution timeout so it won't run forever
    if execution_timeout > 0:
        _set_timeout(execution_timeout, run_name)

    # get to initialise redis process
    persistence.default_db()


def _alarm_handler(_, dummy, callback=None):
    """
    B{Global alarm signal handler to be invoked everytime an alarm signal is received; ensures everything is shut down gracefully}

    NOTE: This function is only invoked by the Python Runtime if the signal is received; this function should never be directly invoked

    @type _: string
    @param _: Signal number
    @type dummy: string
    @param dummy: Stack frame
    @type callback: string
    @param callback: custom signal handler function to call for tool specific actions
    @rtype: void
    """

    if log.logger is not None:
        log.logger.warn("\nTool execution timeout reached; tearing down...")
    else:
        print log.yellow_text("\nTool execution timeout reached; tearing down...")

    exit(4, callback)


def _set_timeout(timeout_value, run_name):
    """
    B{Sets a signal handler for an alarm. Then sets an alarm to happen after a specified amount of seconds, which is the execution timeout. If the application execution takes longer than this timeout, the handler is called and terminates execution.}

    @type timeout_value: string
    @param timeout_value: application timeout value to be set
    @rtype: void
    """

    signal.signal(signal.SIGALRM, _alarm_handler)

    try:
        timeout_value = int(timeout_value)
    except:
        exception.process_exception("Exception raised when trying to convert %s to integer" % timeout_value, True)

    log.logger.debug("Setting timeout of {1}s for {0} execution.".format(run_name, timeout_value))
    signal.alarm(timeout_value)


def signal_handler(_, dummy, callback=None):
    """
    B{Global signal handler to be invoked if a termination signal is received; ensures everything is shut down gracefully}

    NOTE: This function is only invoked by the Python Runtime if the signal is received; this function should never be directly invoked

    @type _: string
    @param _: Signal number
    @type dummy: string
    @param dummy: Stack frame
    @type callback: string
    @param callback: custom signal handler function to call for tool specific actions
    @rtype: void
    """

    if log.logger is not None:
        log.logger.warn("\nSignal received; shutting down...")
    else:
        print log.yellow_text("\nSignal received; shutting down...")

    cache.set("block_exception_handling", True)
    exit(5, callback)


def exit(rc=5, callback=None):  # pylint: disable=redefined-builtin
    """
    B{Shuts down the system, including any threads if running multi-threaded code}

    @type rc: int
    @param rc: Return code to exit with
    @type callback: string
    @param callback: custom signal handler function to call for tool specific actions
    @rtype: void
    """

    if log.logger is not None:
        log.logger.debug("RETURN CODE: Main process is exiting with return code {0}".format(rc))

    # Make sure we have an integer return code
    try:
        rc = int(rc)
    except:
        rc = 5

    # If we're exiting abnormally, let the user know
    if rc == 5:
        if log.logger is not None:
            log.logger.info(log.red_text("Terminating all threads and shutting down script..."))
        else:
            print log.red_text("Terminating all threads and shutting down script...")

    # If we have a callback to invoke, signal to multitasking that we need to wait for all threads to join before returning
    wait_for_threads_to_finish = False
    if callback is not None:
        wait_for_threads_to_finish = True

    # If we have any threads running, kill them as well
    try:
        multitasking.terminate_threads(wait_for_threads_to_finish)
    except:
        exception.process_exception("Unable to terminate all threads")

    # If we were given an explicit callback, execute that now before we tear down further
    if callback is not None:
        try:
            callback()
            multitasking.terminate_threads(False)
        except:
            exception.process_exception("Exception raised during custom callback execution")

    # Remove all persistence backed mutexes before exiting
    mutexer.terminate_mutexes()

    # Shutdown logging and clear persistence if we need to
    try:
        # Clear persistence if this if we're exiting abnormally
        if rc == 5:
            persistence.clear()

        log.log_shutdown()
    except:
        pass

    os._exit(rc)
