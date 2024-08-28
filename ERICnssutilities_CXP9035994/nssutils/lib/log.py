import atexit
import inspect
import itertools
import logging
try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass
import multiprocessing.queues
import os
import pkgutil
import signal
import sys
import threading
import time

import config
import filesystem
import log_mgr
import multitasking
import mutexer
import persistence


NSSUTILS_PATH = pkgutil.get_loader('nssutils').filename
LOCAL_LOG_DIR = os.path.join(NSSUTILS_PATH, '..', '..', 'logs')

logger = None
log_queue = None
manager = None
WORKLOAD_LOG_LEVEL = 17
SYSLOG_LOG_LEVEL = 25
EXCEPTION_LOG_LEVEL = 45

RED_TEXT_COLOUR = '\033[91m'
NORMAL_TEXT = '\033[0m'
YELLOW_TEXT_COLOUR = '\033[33m'
CYAN_TEXT_COLOUR = '\033[96m'
BLUE_TEXT_COLOUR = '\033[94m'
GREEN_TEXT_COLOUR = '\033[92m'
PURPLE_TEXT_COLOUR = '\033[95m'
WHITE_TEXT_COLOUR = '\033[97m'
UNDERLINE_TEXT = '\033[4m'


# Bug in ENMscripting which adds streamhandler to the root logger.
logging.getLogger().addHandler(NullHandler())


def log_workload(_, severity, profile_name, msg):
    """
    Logs a WORKLOAD message to the logging subsystem

    NOTE: This function is used by the simplified logging framework and is injected into the simplified logger

    :param: severity: The log message severity (one of INFO, WARN or ERROR)
    :type: severity: str
    :param: profile_name: The name of the workload profile logging the message
    :type: profile_name: str
    :param: msg: Message to be logged
    :type: msg: str

    :rtype: None

    """

    # Pack all data values into a single string
    msg = "||||".join([severity, profile_name, str(os.getpid()), msg])
    persistence.publish("workload-log", msg)


def log_exception(self, msg_list, *args, **kwargs):
    """
    Logs an EXCEPTION message to the logging subsystem

    NOTE: This function is used by the simplified logging framework and is injected into the simplified logger

    :param: msg_list: list of exception message containing stack trace
    :type: msg_list: list

    :rtype: None

    """
    for line in msg_list:
        self.log(EXCEPTION_LOG_LEVEL, line, *args, **kwargs)


def log_syslog(self, msg, *args, **kwargs):
    """
    Logs a SYSLOG message to the logging subsystem (and out to syslog)

    NOTE: This function is used by the simplified logging framework and is injected into the simplified logger

    :param: msg: Message to be logged
    :type: msg: str

    :rtype: None

    """

    self.log(SYSLOG_LOG_LEVEL, msg, *args, **kwargs)


def log_cmd(_, description, rc, output):
    """
    Logs a SYSLOG message to the logging subsystem (and out to syslog)

    NOTE: This function is used by the simplified logging framework and is injected into the simplified logger

    :param: _self: Object instance passed when function called from method
    :type: _self: Object
    :param: description: Description of the command that was run
    :type: description: str
    :param: rc: Return code produced by the command
    :type: rc: str
    :param: output: Output produced by the command
    :type: output: str

    :rtype: None

    """

    with mutexer.mutex("log-cmd"):
        logger.debug(description)
        logger.debug("  Command return code: %s" % rc)

        lines = []
        if output is not None:
            lines = output.strip().split("\n")

        if len(lines) == 0 or len(lines[0].strip()) == 0:
            logger.debug("  Command produced no output")
        elif len(lines) == 1 and len(lines[0].strip()) > 0:
            logger.debug("  Command output: " + lines[0])
        else:
            logger.debug("  Command output: ")
            for line in lines:
                line = line.strip()
                logger.debug("    " + line)


def test_log_init():
    """
    Tests the initialization of loggers and the logging subsystem

    :return: void

    """
    global logger

    # Create a new logger but don't register any handlers; any log messages will simply be discarded
    logging.raiseExceptions = False
    logger = logging.getLogger("nssutilities-test")
    logger.addHandler(NullHandler())

    # Register a new function with the Logger class for our workload logger
    logging.Logger.workload = log_workload


def simplified_log_init(identifier, overwrite=False, log_dir=None):
    """
    Initializes a simplified logging subsystem for non-main threads and processes

    :param: identifier: Unique identifier for the thread or process initializing simplified logging
    :type: identifier: string
    :param: overwrite: Flag controlling whether the existing log file will be overwritten (if it exists)
    :type: overwrite: boolean
    :param: log_dir: path to store logs in (defaults to prop)
    :type: log_dir: str

    :rtype: None

    """

    global logger

    logging.raiseExceptions = False

    class LogFormatter(logging.Formatter):

        def format(self, record):
            ct = self.converter(record.created)
            t = time.strftime("%Y-%m-%d %H:%M:%S", ct)
            timestamp = "%s,%03d" % (t, record.msecs)
            msg = record.msg.replace('\033[91m', '').replace('\033[94m', '').replace('\033[92m', '').replace('\033[95m', '').replace('\033[33m', '').replace('\033[0m', '').replace('\033[96m', '').replace('\033[97m', '').replace('\033[4m', '').rstrip()
            final_msg = "%s %s %s" % (timestamp, record.levelname.ljust(7), msg)

            # Append the thread ID if this isn't the main thread logging
            try:
                thread_id = threading.current_thread().name
            except:
                thread_id = None

            if thread_id is not None and "MainThread" not in thread_id:
                final_msg = "{0} (thread ID {1})".format(final_msg, thread_id)

            return final_msg

    # Initialize the new logger
    logging.addLevelName(WORKLOAD_LOG_LEVEL, "WORKLOAD")
    logging.addLevelName(SYSLOG_LOG_LEVEL, "SYSLOG")
    logging.addLevelName(EXCEPTION_LOG_LEVEL, "EXCEPTION")
    logger = logging.getLogger("nssutilities-simple")
    logger.setLevel(logging.DEBUG)
    formatter = LogFormatter("%(asctime)s %(levelname)s %(message)s")

    # Register functions with the Logger class for our custom log levels
    logging.Logger.exception = log_exception
    logging.Logger.syslog = log_syslog
    logging.Logger.log_cmd = log_cmd
    logging.Logger.workload = log_workload

    log_dir = log_dir or os.path.join(config.get_log_dir(), "daemon")

    # Make sure our log directory exists
    filesystem.create_dir(log_dir)

    # Set up our debug log handler
    log_file = os.path.join(log_dir, identifier + ".log")

    if overwrite and os.path.exists(log_file):
        os.remove(log_file)

    handler = log_mgr.CompressedRotatingFileHandler(log_file, maxBytes=log_mgr.MAX_BYTES_SIZE, backupCount=3)
    handler.set_name(identifier)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def shutdown_handlers(identifier=None):
    """
    Stops simplified logging subsystem and remove handlers for non-main threads and processes

    :param: identifier: Unique identifier for simplified logging
    :type: identifier: string

    :rtype: None

    """
    global logger

    # This will shutdown the logging subsystem, but it will continue to write to any attached
    # file handlers even after shutingdown. So the workaround is to remove any file handlers
    # attached to the logger after shutting down the logging system
    logging.shutdown()

    # Remove the handlers
    for handler in logger.handlers:
        logger.removeHandler(handler)
        # Only remove the specified handler if identifier is provided otherwise remove all
        if identifier is not None and handler.name == identifier:
            break


def _prepare_log_dir(log_path):
    """
    Prepare log directory for future logging

    :param: log_path: Absolute path to the logging dir
    :type: log_path: str
    """
    # Problems occur when path exists but is not a dir, in this case file should be removed. CIS-33715
    if os.path.exists(log_path) and not os.path.isdir(log_path):
        os.remove(log_path)
    if not os.path.isdir(log_path):
        os.makedirs(log_path)


def log_init():
    """
    Initializes loggers and the logging subsystem

    :rtype: None
    """

    global logger
    global log_queue
    global manager

    # Make sure our log dir exists
    log_path = config.get_log_dir()
    _prepare_log_dir(log_path)
    if not os.path.isdir(log_path):
        raise RuntimeError("Could not create log directory " + log_path)

    # Register the shutdown function to run at exit
    atexit.register(log_shutdown)

    # Create a shared memory queue that will be used to transport log entries from all threads and processes to the log process
    log_queue = multiprocessing.Queue()

    # Create a proxy class that will forward all log messages to the logging process via the shared memory queue
    class ProxyLogger(object):
        module_id = "ProxyLogger"

        def get_caller(self):
            return inspect.stack()[2][3]

        def get_identifier(self):
            try:
                thread_id = threading.current_thread().name
            except:
                thread_id = None

            if thread_id is not None and "MainThread" not in thread_id:
                return "(thread ID " + str(thread_id) + ")"

            try:
                proc_id = multiprocessing.current_process().name
            except:
                proc_id = None

            if proc_id is not None and "MainProcess" not in proc_id:
                return "(process ID " + str(proc_id) + " [PID " + str(multiprocessing.current_process().pid) + "])"

            return ""

        def log_cmd(self, description, rc, output):
            caller = self.get_caller()
            identifier = self.get_identifier()

            with mutexer.mutex(ProxyLogger.module_id):
                log_queue.put(["DEBUG", description, caller, identifier])
                log_queue.put(["DEBUG", "  Command return code: " + rc, caller, identifier])

                lines = []
                if output is not None:
                    lines = output.strip().split("\n")

                if len(lines) == 0 or len(lines[0].strip()) == 0:
                    log_queue.put(["DEBUG", "  Command produced no output", caller, identifier])
                elif len(lines) == 1 and len(lines[0].strip()) > 0:
                    log_queue.put(["DEBUG", "  Command output: " + lines[0], caller, identifier])
                else:
                    log_queue.put(["DEBUG", "  Command output: ", caller, identifier])
                    for line in lines:
                        line = line.strip()
                        log_queue.put(["DEBUG", "    " + line, caller, identifier])

        def debug(self, msg):
            log_queue.put(["DEBUG", msg, self.get_caller(), self.get_identifier()])

        def info(self, msg):
            log_queue.put(["INFO", msg, self.get_caller(), self.get_identifier()])

        def warn(self, msg):
            log_queue.put(["WARNING", msg, self.get_caller(), self.get_identifier()])

        def rest(self, msg):
            log_queue.put(["REST", msg, self.get_caller(), self.get_identifier()])

        def error(self, msg):
            log_queue.put(["ERROR", msg, self.get_caller(), self.get_identifier()])

        def syslog(self, msg):
            log_queue.put(["SYSLOG", msg, self.get_caller(), self.get_identifier()])

        def workload(self, severity, profile_name, msg):
            # Pack all data values into a single string
            msg = "||||".join([severity, profile_name, str(os.getpid()), msg])
            persistence.publish("workload-log", msg)

        def exception(self, lines):
            caller = self.get_caller()
            identifier = self.get_identifier()

            with mutexer.mutex(ProxyLogger.module_id):

                for line in lines:
                    log_queue.put(["EXCEPTION", line, caller, identifier])
                    log_queue.put(["DEBUG", line, caller, identifier])

    logger = ProxyLogger()

    logger.debug("")
    logger.debug("")
    logger.debug("")

    # Initialize the log manager process
    manager = multitasking.UtilitiesProcess(target=log_mgr.UtilitiesLogManager, args=[log_queue])
    manager.daemon = True
    manager.start()

    # Log a message that logging is initialized
    logger.debug("Initialized logging successfully")


def log_shutdown():
    """
    Shuts down the logging sub-system

    :rtype: None

    """

    global logger
    global manager

    if logger is not None:
        logger.debug("Shutting down logging subsystem")

    # Give the log manager some time to clear the log queue
    counter = 0
    while not log_queue.empty() and counter < 6:
        time.sleep(.05)
        counter = counter + 1

    # One last sleep should allow the log manager to flush the last entries
    time.sleep(.05)

    # Disable further logging
    logger = None

    # Terminate the log manager process
    try:
        os.kill(manager.pid, signal.SIGKILL)

        # Shutdown the logging subsystem
        logging.shutdown()
    except:
        pass


def clear_colors(msg):
    """
    Clears ANSI color codes from the specified string

    :param: msg: string to be de-colorized
    :type: msg: string

    :returns: string cleared from ANSI color codes
    :rtype: string

    """

    return msg.replace('\033[91m', '').replace('\033[94m', '').replace('\033[92m', '').replace('\033[95m', '').replace('\033[33m', '').replace('\033[0m', '').replace('\033[96m', '').replace('\033[97m', '')


def clear_underline(msg):
    """
    Clears underline codes from the specified string

    :param: msg: string to clear underline
    :type: msg: string

    :returns: modified string
    :rtype: string

    """

    return msg.replace('\033[4m', '')


def _check_use_color():
    """
    Returns True or false depending on 'print_color' flag in config file

    :returns: True or false depending on 'print_color' flag in config file
    :rtype: boolean

    """
    if config.get_prop("print_color").strip().lower() == "true":
        return True
    else:
        return False


def red_text(text):
    """
    Returns the specified text in red color

    :param: text: the text to be colorized
    :type: text: string

    :rtype: string

    """

    if _check_use_color():
        return "%s%s%s" % (RED_TEXT_COLOUR, text, NORMAL_TEXT)
    else:
        return text


def yellow_text(text):
    """
    Returns the specified text in yellow color

    :param: text: the text to be colorized
    :type: text: string

    :rtype: string

    """

    if _check_use_color():
        return "%s%s%s" % (YELLOW_TEXT_COLOUR, text, NORMAL_TEXT)
    else:
        return text


def blue_text(text):
    """
    Returns the specified text in blue color

    :param: text: the text to be colorized
    :type: text: string

    :rtype: string

    """

    if _check_use_color():
        return "%s%s%s" % (BLUE_TEXT_COLOUR, text, NORMAL_TEXT)
    else:
        return text


def green_text(text):
    """
    Returns the specified text in green color

    :param: text: the text to be colorized
    :type: text: string

    :rtype: string

    """

    if _check_use_color():
        return "%s%s%s" % (GREEN_TEXT_COLOUR, text, NORMAL_TEXT)
    else:
        return text


def purple_text(text):
    """
    Returns the specified text in purple color

    :param: text: the text to be colorized
    :type: text: string

    :rtype: string

    """

    if _check_use_color():
        return "%s%s%s" % (PURPLE_TEXT_COLOUR, text, NORMAL_TEXT)
    else:
        return text


def cyan_text(text):
    """
    Returns the specified text in cyan color

    :param: text: the text to be colorized
    :type: text: string

    :rtype: string

    """

    if _check_use_color():
        return "%s%s%s" % (CYAN_TEXT_COLOUR, text, NORMAL_TEXT)
    else:
        return text


def white_text(text):
    """
    Returns the specified text in white color

    :param: text: the text to be colorized
    :type: text: string

    :rtype: string

    """

    if _check_use_color():
        return "%s%s%s" % (WHITE_TEXT_COLOUR, text, NORMAL_TEXT)
    else:
        return text


def underline_text(text):
    """
    Returns the specified text with underlining applied

    :param: text: the text to be colorized
    :type: text: string

    :rtype: string

    """

    if _check_use_color():
        return "%s%s%s" % (UNDERLINE_TEXT, text, NORMAL_TEXT)
    else:
        return text


def get_log_level_color(level, text):
    """
    Returns colorized text based on the log level of the message

    :param: level: Log level of the message
    :type: level: string
    :param: text: Message to be logged
    :type: text: string

    :returns: colorized text based on the log level
    :rtype: string

    """

    level = level.upper()

    if 'ALL' in level:
        val = purple_text(text)
    elif "TRACE" in level:
        val = white_text(text)
    elif "DEBUG" in level:
        val = white_text(text)
    elif "INFO" in level:
        val = cyan_text(text)
    elif "WARN" in level:
        val = yellow_text(text)
    elif "ERROR" in level:
        val = red_text(text)
    elif "FATAL" in level:
        val = red_text(text)
    else:
        val = text
    return val


def log_entry(parameters=None):
    """
    Logs the entry into a function

    :param: parameters: all parameters passed to function
    :type: parameters: string

    :rtype: None

    """

    if logger is not None:
        try:
            stack = inspect.stack()
        except IndexError as e:
            stack = []
            # Error in relation to 'code.activestate.com/lists/python-list/585140/'
            logger.debug("Exception occurred in log_entry: {0}".format(str(e)))

        if len(stack) >= 1:
            caller_frame = inspect.stack()[1]
            calling_module = inspect.getmodulename(caller_frame[1])
            calling_function = caller_frame[3]

            if calling_module is not None and calling_function is not None:
                msg = "  Entering {0}.{1}".format(calling_module, calling_function)

                if parameters is not None:
                    msg = msg + "({0})...".format(parameters)
                else:
                    msg = msg + "()..."

                logger.debug(msg)


def console_log_http_request(http_request, response):
    """
    Prints the results of the output if for verbose mode is true

    :param: http_request: The HTTP request
    :type: http_request: object <http.Request>
    :param: response: The HTTP response from the request
    :type: response: object <http.Response>

    :rtype: None

    """

    output_list = list()

    output_list.append("  Issued HTTP {0} request".format(http_request.method.upper()))
    output_list.append("    URL: {0}".format(http_request.url))

    if http_request.headers is not None:
        output_list.append("    Headers: {0}".format(http_request.headers))

    if http_request.data is not None:
        output_list.append("    Data: {0}".format(http_request.data))

    if http_request.json is not None:
        output_list.append("    Data (JSON): {0}".format(http_request.json))

    if http_request.params is not None:
        output_list.append("    Params: {0}".format(http_request.params))

    output_list.append("  Response:")
    output_list.append("    Output: {0}".format(str(response.output)))

    for output in output_list:
        logger.info(output)


def log_console_flash_message(log_message):
    """
    B{Logs a message to the console that will be overwritten by subsequent message}

    @type log_message: str
    @param log_message: Log message to output to console and debug.log
    """
    from sys import stdout

    logger.debug(log_message)
    stdout.write(log_message + "\r")
    stdout.flush()


class Spinner(object):
    """
    B{Starts a thread and prints spinner to left margin of console}

    Usage: Create an instance, start the spinner, do some work, stop the spinner

        spinner = Spinner()
        spinner.start()
        do_some_work()
        spinner.stop()
    """

    spinner_cycle = itertools.cycle(['-', '/', '|', '\\'])

    def __init__(self):
        self.stop_running = threading.Event()
        self.spin_thread = threading.Thread(target=self.init_spin)

    def start(self):
        self.spin_thread.start()

    def stop(self):
        self.stop_running.set()
        self.spin_thread.join()

    def init_spin(self):
        while not self.stop_running.is_set():
            sys.stdout.write(self.spinner_cycle.next())
            sys.stdout.flush()
            time.sleep(0.25)
            sys.stdout.write('\b')
