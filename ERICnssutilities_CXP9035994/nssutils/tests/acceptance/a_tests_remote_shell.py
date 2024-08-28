#!/usr/bin/env python
import threading

import unittest2

from nssutils.lib import shell
from nssutils.tests import func_test_utils, test_fixture
from nssutils.tests.func_test_utils import func_dec

REMOTE_TEST_HOST = "svc-1-pmserv"
REMOTE_TEST_USER = "cloud-user"


class RemoteShellAcceptanceTests(unittest2.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fixture = test_fixture.AcceptanceTestFixture(cls)

    @classmethod
    def tearDownClass(cls):
        func_test_utils.module_tear_down(cls)

    def setUp(self):
        func_test_utils.setup(self)

    def tearDown(self):
        func_test_utils.tear_down(self)

    @func_dec("Shell Library", "Execute command on a remote host that requires a password to establish the connection")
    def test_successful_remote_command_with_password_produces_return_code_zero(self):
        cmd = shell.Command("hostname", timeout=10)
        resp = shell.run_remote_cmd(cmd, "netsim", "netsim", "netsim")
        self.assertEqual(0, resp.rc)

    @func_dec("Shell Library", "Unsuccessful remote command execution produces non-zero return code")
    def test_unsuccessful_remote_command_produces_non_zero_return_code(self):
        cmd = shell.Command("adfasdfasdfadadfasdfasda", timeout=5)
        resp = shell.run_remote_cmd(cmd, REMOTE_TEST_HOST, REMOTE_TEST_USER)
        self.assertNotEqual(0, resp.rc)

    @func_dec("Shell Library", "Remote command execution exceeding timeout is forcibly terminated")
    def test_remote_command_exceeding_timeout_is_terminated(self):
        cmd = shell.Command("sleep 1", timeout=.1)
        resp = shell.run_remote_cmd(cmd, REMOTE_TEST_HOST, REMOTE_TEST_USER)
        command_timeout_rc = 177
        self.assertEqual(command_timeout_rc, resp.rc)

    @func_dec("Shell Library", "Interrupted remote command execution produces return code indicating connection closed")
    def test_interrupted_remote_command_returns_connection_closed_return_code(self):
        cmd = shell.Command("sleep 5", timeout=10)
        connection = shell.get_connection_mgr().get_connection(REMOTE_TEST_HOST, REMOTE_TEST_USER)
        executor = shell.RemoteExecutor(cmd, connection)

        # Define a function to kill our connection
        def killer(connection):
            connection.close()

        # Kick off a timer thread to invoke our killer
        threading.Timer(.2, killer, [connection]).start()

        # Run the command
        response = executor.execute()
        command_connection_closed_rc = 255
        self.assertEqual(command_connection_closed_rc, response.rc)
        self.assertEqual("", response.stdout)


if __name__ == "__main__":
    unittest2.main(verbosity=2)
