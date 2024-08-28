import sys
import traceback

import cache
import init
import log
import mutexer
import timestamp


def process_exception(msg=None, fatal=False, print_msg_to_console=False):
    """
    B{Processes and logs an exception to the debug and exception logs}

    @type msg: string
    @param msg: Custom message to be printed with exception stack trace
    @type fatal: boolean
    @param fatal: Flag controlling whether the exception is fatal and should trigger a shutdown
    @type print_msg_to_console: boolean
    @param print_msg_to_console: Flag controller whether to print the error message to the console
    @rtype: void
    """

    if not cache.has_key("block_exception_handling"):
        exception_lines = []

        with mutexer.mutex("process-exception"):
            # Print out any custom messages we may have been passed
            exception_lines.append("")
            if msg is not None:
                exception_lines.append(msg + " [" + timestamp.get_human_readable_timestamp() + "]")
                exception_lines.append("")

            # Get the base exception objects
            (exc_type, exc_value, exc_traceback) = sys.exc_info()
            if exc_type is not None and exc_value is not None and exc_traceback is not None:
                # Print out the exception
                exception_lines.append("EXCEPTION: " + str(exc_type.__name__) + " - " + str(exc_value))
                exception_lines.append("")
                exception_lines.append("STACK TRACE")
                exception_lines.append("-----------")
                exception_lines.append("")

                # Get the exception stack as a list
                exception_list = traceback.extract_tb(exc_traceback)
                for counter in range((len(exception_list) - 1), -1, -1):
                    exception_tuple = exception_list[counter]
                    if len(exception_tuple) >= 4:
                        filename = exception_tuple[0]
                        line_num = exception_tuple[1]
                        function_name = exception_tuple[2]
                        line = exception_tuple[3]

                        # Print out the standard exception info
                        if "<module>" in function_name:
                            exception_lines.append("[" + str(counter + 1) + "] LINE " + str(line_num) + " OF FILE " + filename)
                        elif exc_traceback is not None:
                            exception_lines.append("[" + str(counter + 1) + "] LINE " + str(line_num) + " OF FILE " + filename)
                        else:
                            exception_lines.append("[" + str(counter + 1) + "] LINE " + str(line_num) + " OF FILE " + filename)

                        if line is not None and len(line) > 0:
                            exception_lines.append("    LINE: " + line.strip())

            exception_lines.append("")

            # Log the exception
            log.logger.exception(exception_lines)

            # Print error message to console if needed
            if print_msg_to_console:
                log.logger.error(msg)

        # If this is a fatal exception, shutdown
        if fatal:
            init.exit(5)


def handle_exception(tool_name, msg=None, rc=5):
    """
    B{Exception handler for tools that will log raised exceptions and shutdown}

    NOTE: This function should only be invoked by top-level tools, never directly by API modules

    @type tool_name: string
    @param tool_name: The name of the tool. This can be obtained using the __file__ attribute
    @type msg: string
    @param msg: Custom message to be printed with exception stack trace
    @type rc: int
    @param rc: Return code to exit with
    @rtype: void
    """

    if msg is None:
        msg = "Encountered an unhandled exception while running tool " + tool_name

    # Print the error message
    log.logger.error(msg + " [" + timestamp.get_human_readable_timestamp() + "]")

    (_, exc_value, _) = sys.exc_info()
    if exc_value is not None:
        log.logger.error(str(exc_value))

    log.logger.error("")

    # Capture and log the stack trace
    process_exception(msg)

    # Shutdown
    init.exit(rc)


def handle_invalid_argument(msg=None):
    """
    B{Exception handler for tools when invalid arguments are supplied}

    NOTE: This function should only be invoked by top-level tools, never directly by API modules

    @type msg: string
    @param msg: Custom message to be printed to the user
    @rtype: void
    """

    # If a custom message is given print it
    log.logger.error("\nERROR: Command line argument validation has failed.")
    if msg is not None:
        log.logger.error("  " + msg)
    else:
        log.logger.error("  Invalid command line arguments")

    log.logger.error("  Please run the tool with '-h' or '--help' for more information about command line arguments and supported values.\n")

    init.exit(2)
