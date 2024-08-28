#!/usr/bin/env python
import os
import pkgutil
import sys
import subprocess
from functools import wraps

import nose

from nssutils.lib import cache, config, exception, init, log, persistence, shell
from nssutils.lib.deprecated import session_mgr
from nssutils.tests import test_utils

log_counter = 1

INTERNAL = pkgutil.get_loader('nssutils').filename


def setup(cls):
    """
    B{Sets up a functional test execution}

    @type cls: unittest2.TestCase
    @param cls: Test class to be run

    @rtype: void
    """

    global log_counter
    log_counter = 1

    try:
        init.global_init("func-test", "prod", cls._testMethodName, simplified_logging=True)

        # Set environment variable to 'testing' so config picks up the test database index when calling default db
        log.logger.debug("func_test_utils setup - Setting ENVIRON=testing")
        config.set_prop("ENVIRON", "testing")

        # NOTE: The persistence object gets created here as session mgr is the first to persist something
        log.logger.debug("Establishing security admin session for test case {0}".format(cls._testMethodName))
        session_mgr.establish_security_admin_session()
        test_utils.setup()

        if hasattr(cls, "fixture"):
            cls.fixture.setup()

        log.logger.debug("Test setup has finished; executing test...")

    except BaseException as e:
        exception.process_exception("Exception raised during test setup: {0}".format(e.message))
        tear_down(cls)
        raise


def tear_down(cls):
    """
    B{Tears down after a functional test execution}

    @type cls: unittest2.TestCase
    @param cls: Test class to be cleaned after test method execution has finished

    @rtype: void
    """

    log.logger.debug("Test has finished; tearing down...")
    shell.delete_connection_mgr()

    test_name = cls._testMethodName
    log.shutdown_handlers(test_name)

    if test_name is not None and hasattr(nose, 'allure'):
        log_file_path = os.path.join(config.get_log_dir(), "test", "{0}.log".format(test_name))
        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as file_handle:
                nose.allure.attach("Test Log", file_handle.read())


def module_tear_down(cls):
    """
    B{Tears down after all functional tests have been executed in the specified test class}

    @type cls: unittest2.TestCase
    @param cls: Test class to be cleaned up

    @rtype: void
    """

    try:
        tear_down_result = True
        log_name = "{0}TearDown".format(cls.__name__)
        init.global_init("func-test", "int", log_name, simplified_logging=True)

        if hasattr(cls, "fixture"):
            tear_down_result = cls.fixture.teardown()

        cache.clear()
        if not persistence.default_db().clear_all():
            log.logger.info("DB not cleared")
        persistence.mutex_db().clear()
        log.shutdown_handlers(log_name)

        if hasattr(nose, 'allure'):
            log_file_path = os.path.join(config.get_log_dir(), "test", "{0}.log".format(log_name))
            if os.path.exists(log_file_path):
                with open(log_file_path, "r") as file_handle:
                    nose.allure.attach("Teardown Log", file_handle.read())

        if not tear_down_result:
            raise RuntimeError("Error occurred in teardown steps. Check logs for more details.")

    except BaseException as e:
        exception.process_exception("Exception raised during teardown of test module {0}: {1}"
                                    .format(cls.__name__, e.args[0]))
        raise


def _execute_cmd(cmd, return_output=False):
    """
    B{Executes a command in a local shell and returns the return code or output}

    :type cmd: str
    :param cmd: Command to be run
    :type return_output: bool
    :param return_output: Toggles whether the command output should be returned instead of the command return code

    :rtype: void
    """

    # Execute the command
    log.logger.info("Executing command '{0}'".format(cmd))
    pipe = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    output = pipe.communicate()[0].strip()
    rc = pipe.returncode
    log.logger.info("Command return code: {0}".format(rc))

    # Return whatever we've been asked to return
    if return_output:
        return output

    return rc


def assert_command_produces_expected_rc(test, cmd, expected_rc, msg=None):
    """
    B{Executes a command in a local shell and returns the return code or output}

    @type test: unittest2.TestCase
    @param test: Testcase being executed
    @type cmd: str
    @param cmd: Command to be run
    @type expected_rc: int
    @param expected_rc: The return code that the command is expected to produce
    @type msg: str
    @param msg: Message to be displayed if the actual return code does not match the expected return code

    @rtype: void
    """

    actual_rc = _execute_cmd(cmd)

    if actual_rc != expected_rc:
        sys.stderr.write("\nFAIL: Command was expected to produce return code of {0}, "
                         "but actually produced return code of {1}".format(expected_rc, actual_rc))
        if msg is not None:
            sys.stderr.write("\n   {0}".format(msg))

        sys.stderr.write("\n   Command: {0}\n\n".format(cmd))
        sys.stderr.flush()
        test.fail("FAIL: Command was expected to produce return code of {0}, "
                  "but actually produced return code of {1}".format(expected_rc, actual_rc))


def func_dec(feature=None, story=None, issue=None):
    """
    B{Adds allure annotations to acceptance tests}

    @type feature: string
    @param feature: Feature name for allure plugin
    @type story: string
    @param story: Story name for allure plugin
    @type issue: string
    @param issue: Issue for allure plugin

    @rtype: func
    @rtype param: Returns decorated function with allure annotations
    """

    def wrapper(func):
        def wrapped(*args, **kwargs):
            return func(*args, **kwargs)

        if hasattr(nose, "allure"):
            wrapped = wraps(func)(wrapped)
            if issue:
                wrapped = nose.allure.issue(issue)(wrapped)
            if feature and story:
                wrapped = nose.allure.feature(feature)(wrapped)
                wrapped = nose.allure.story(story)(wrapped)

        return wrapped
    return wrapper
