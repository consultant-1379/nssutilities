import sys
import os
import time
import logging
import logging.handlers
import signal
import gzip
import shutil
import multiprocessing
import threading
import traceback
# These modules are imported relatively from current python package i.e. lib
# and to avoid circular imports we cannot do from . import ...
import config
import log
# End circular imports


MAX_BYTES_SIZE = 314572800


class CompressedRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
   Extended version of TimedRotatingFileHandler that compress logs on rollover.

    """
    def __init__(self, *args, **kwargs):
        super(CompressedRotatingFileHandler, self).__init__(*args, **kwargs)
        self.doing_rollover = False

    def doRollover(self):
        """
        Do a rollover, as described in __init__().
        """
        if self.stream:
            self.stream.close()
            self.stream = None
        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = "%s.%d.gz" % (self.baseFilename, i)
                dfn = "%s.%d.gz" % (self.baseFilename, i + 1)
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)
            dfn = self.baseFilename + ".1.gz"
            if os.path.exists(dfn):
                os.remove(dfn)
            # A file may not have been created if delay is True.
            if os.path.exists(self.baseFilename):
                new_name = self.baseFilename + '.1'
                os.rename(self.baseFilename, new_name)
                with open(new_name, 'rb') as f_in, gzip.open(new_name + '.gz', 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.remove(new_name)
        if not self.delay:
            self.stream = self._open()

    def shouldRollover(self, record):
        """
        Determine if rollover should occur.
        Basically, see if the supplied record would cause the file to exceed
        the size limit we have.
        """
        self.acquire()
        try:
            return super(CompressedRotatingFileHandler, self).shouldRollover(record)
        finally:
            self.release()


class UtilitiesLogManager(object):
    # Constructor

    def __init__(self, queue):
        """
        Constructs UtilitiesLogManager

        :param queue: log values
        :type queue: dict

        :returns: void

        """
        self.queue = queue
        self.logger = None
        self.exception_logger = None
        self.syslog_logger = None

        # Initialize formatters and handlers
        self.init()

        # Wait for and process log entries
        self.process_logs()

    def init(self):
        """
        Initializes the log manager

        :rtype: None

        """

        # Replace SIGINT with SIGIGN so that we don't get whacked by a SIGINT propagated from the parent process on a keyboard interrupt
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Use a custom formatter so that we can strip color codes from the messages going to log files
        class ConsoleFormatter(logging.Formatter):

            def format(self, record):
                """
                Formats the log msg send to the console

                :param record: log data
                :type record: string

                :return: final msg
                :rtype: string

                """
                # Colorize output based on log level
                level = record.levelname.ljust(7)
                final_msg = "%s" % record.msg
                if "error" in level.lower():
                    final_msg = log.red_text(final_msg)
                elif "warning" in level.lower():
                    final_msg = log.yellow_text(final_msg)

                return final_msg

        class LogFormatter(logging.Formatter):

            def format(self, record):
                """
                Formats the log msg for logging

                :param record: log data
                :type record: string

                :return: final msg
                :rtype: string

                """
                ct = self.converter(record.created)
                t = time.strftime("%Y-%m-%d %H:%M:%S", ct)
                timestamp = "%s,%03d" % (t, record.msecs)
                msg = record.msg.replace('\033[91m', '').replace('\033[94m', '').replace('\033[92m', '').replace('\033[95m', '').replace('\033[33m', '').replace('\033[0m', '').replace('\033[96m', '').replace('\033[97m', '').rstrip()
                final_msg = "%s %s %s" % (timestamp, record.levelname.ljust(7), msg)
                return final_msg

        class DebugLogFormatter(logging.Formatter):

            def format(self, record):
                """
                Log debugger

                :param record: log data
                :type record: string

                :return: final msg
                :rtype: string

                """
                ct = self.converter(record.created)
                t = time.strftime("%Y-%m-%d %H:%M:%S", ct)
                timestamp = "%s,%03d" % (t, record.msecs)
                msg = record.msg.replace('\033[91m', '').replace('\033[94m', '').replace('\033[92m', '').replace('\033[95m', '').replace('\033[33m', '').replace('\033[0m', '').replace('\033[96m', '').replace('\033[97m', '').replace('\033[4m', '').rstrip()
                final_msg = "%s %s %s %s %s" % (timestamp, record.levelname.ljust(7), record.caller.ljust(20)[:20], msg, record.id)
                return final_msg

        class ExceptionLogFormatter(logging.Formatter):

            def format(self, record):
                """
                Formats exception logs

                :param record: log data
                :type record: string

                :return: final msg
                :rtype: string

                """
                ct = self.converter(record.created)
                t = time.strftime("%Y-%m-%d %H:%M:%S", ct)
                timestamp = "%s,%03d" % (t, record.msecs)
                msg = record.msg.replace('\033[91m', '').replace('\033[94m', '').replace('\033[92m', '').replace('\033[95m', '').replace('\033[33m', '').replace('\033[0m', '').replace('\033[96m', '').replace('\033[97m', '').replace('\033[4m', '').rstrip()
                final_msg = "%s %s %s %s %s" % (timestamp, record.levelname.ljust(7), record.caller.ljust(20)[:20], msg, record.id)
                return final_msg

        class SyslogFormatter(logging.Formatter):

            def format(self, record):
                """
                Formats system logs

                :param record: log data
                :type record: string

                :return: msg
                :rtype: string

                """
                return "NSSUTILS: %s" % record.msg

        # Get the logger names from the config
        main_logger_name = config.get_prop("logger_name")
        exception_logger_name = config.get_prop("exception_logger_name")
        syslog_logger_name = config.get_prop("syslog_logger_name")

        # Initialize the new logger
        self.logger = logging.getLogger(main_logger_name)
        self.logger.handlers = []
        self.logger.setLevel(logging.DEBUG)
        formatter = ConsoleFormatter("%(message)s")
        log_formatter = LogFormatter("%(asctime)s %(levelname)s %(message)s")
        debug_log_formatter = DebugLogFormatter("%(asctime)s %(levelname)s %(caller)s %(message)s %(id)s")

        # Set up our console handler
        console_handler = logging.StreamHandler(sys.stdout)
        if config.has_prop("console_log_level") and "debug" in config.get_prop("console_log_level").lower():
            console_handler.setLevel(logging.DEBUG)
        else:
            console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        backup_count = int(config.get_prop("log_backup_count")) if config.has_prop("log_backup_count") else 3
        # Setup our main log handler
        log_handler = CompressedRotatingFileHandler(os.path.join(config.get_log_dir(), config.get_prop("console_log_file")), maxBytes=MAX_BYTES_SIZE, backupCount=backup_count)
        log_handler.setLevel(logging.INFO)
        log_handler.setFormatter(log_formatter)
        self.logger.addHandler(log_handler)

        # Set up our debug log handler
        debug_handler = CompressedRotatingFileHandler(os.path.join(config.get_log_dir(), config.get_prop("debug_log_file")), maxBytes=MAX_BYTES_SIZE, backupCount=backup_count)
        debug_handler.setLevel(logging.DEBUG)

        if config.has_prop("debug_log_level") and "warn" in config.get_prop("debug_log_level").lower():
            debug_handler.setLevel(logging.WARN)

        debug_handler.setFormatter(debug_log_formatter)
        self.logger.addHandler(debug_handler)

        # Initialize & set up the exception logger
        self.exception_logger = logging.getLogger(exception_logger_name)
        self.exception_logger.handlers = []
        self.exception_logger.setLevel(logging.DEBUG)
        exception_formatter = ExceptionLogFormatter("%(asctime)s %(levelname)s %(caller)s %(message)s %(id)s")

        exception_handler = CompressedRotatingFileHandler(os.path.join(config.get_log_dir(), config.get_prop("exception_log_file")), maxBytes=MAX_BYTES_SIZE, backupCount=backup_count)
        exception_handler.setLevel(logging.INFO)
        exception_handler.setFormatter(exception_formatter)
        self.exception_logger.addHandler(exception_handler)

        # Initialize & set up our syslog log handler
        self.syslog_logger = logging.getLogger(syslog_logger_name)
        self.syslog_logger.handlers = []
        self.syslog_logger.setLevel(logging.DEBUG)
        syslog_formatter = SyslogFormatter("%(message)s")

        syslog_handler = logging.handlers.SysLogHandler()
        syslog_handler.setLevel(logging.INFO)
        syslog_handler.setFormatter(syslog_formatter)
        self.syslog_logger.addHandler(syslog_handler)

    def shutdown(self):
        """
        Shuts down the logging sub-system

        :rtype: None

        """

        logging.shutdown()

    def process_logs(self):
        """
        Processes log entries placed on the log queue until terminated

        NOTE: Log entries must be of the form [<level>, <msg>, <caller>, <thread_id/proc_id>]
        NOTE: <thread_id/proc_id> is optional

        :rtype: None

        """

        while True:
            log_entry = self.queue.get()

            if len(log_entry) >= 3:
                level = log_entry[0]
                msg = log_entry[1]

                extra_dict = {}
                extra_dict['caller'] = log_entry[2]
                extra_dict['id'] = ""

                if len(log_entry) == 4:
                    extra_dict['id'] = log_entry[3]

                # Check if message is already unicode before encoding
                try:
                    msg.decode("utf-8")
                    message_already_utf_8 = True
                except UnicodeError:
                    message_already_utf_8 = False

                # Encode the message to unicode before writing to disk
                if not message_already_utf_8:
                    try:
                        msg = msg.encode("utf-8")
                    except BaseException as e:
                        level = "DEBUG"
                        msg = "ERROR: Exception generated encoding message in UTF-8: {0}".format(str(e.args))

                if level == "EXCEPTION":
                    self.exception_logger.info(msg, extra=extra_dict)
                elif level == "SYSLOG":
                    self.syslog_logger.info(msg, extra=extra_dict)
                elif level == "DEBUG":
                    self.logger.debug(msg, extra=extra_dict)
                elif level == "INFO":
                    self.logger.info(msg, extra=extra_dict)
                elif level == "WARNING":
                    self.logger.warn(msg, extra=extra_dict)
                elif level == "ERROR":
                    self.logger.error(msg, extra=extra_dict)


class MultiProcessingLog(logging.Handler):
    def __init__(self, filepath):
        logging.Handler.__init__(self)

        self._handler = logging.FileHandler(filepath)
        self.queue = multiprocessing.Queue(-1)

        t = threading.Thread(target=self.receive)
        t.daemon = True
        t.start()

    def setFormatter(self, fmt):
        logging.Handler.setFormatter(self, fmt)
        self._handler.setFormatter(fmt)

    def receive(self):
        while True:
            try:
                record = self.queue.get()
                self._handler.emit(record)
            except (KeyboardInterrupt, SystemExit):
                raise
            except EOFError:
                break
            except:
                traceback.print_exc(file=sys.stderr)

    def send(self, s):
        self.queue.put_nowait(s)

    def _format_record(self, record):
        # ensure that exc_info and args
        # have been stringified.  Removes any chance of
        # unpickleable things inside and possibly reduces
        # message size sent over the pipe
        if record.args:
            record.msg = record.msg % record.args
            record.args = None
        if record.exc_info:
            self.format(record)
            record.exc_info = None

        return record

    def emit(self, record):
        try:
            s = self._format_record(record)
            self.send(s)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

    def close(self):
        self._handler.close()
        logging.Handler.close(self)
