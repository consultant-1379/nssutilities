#!/usr/bin/env python
import unittest2
from mock import patch

from nssutils.lib import process, shell
from nssutils.tests import unit_test_utils


class ProcessUnitTests(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    @patch('nssutils.lib.shell.run_local_cmd')
    def test_is_pid_running_returns_true_with_D_in_response(self, mock_run_local_cmd):
        response = shell.Response(1, "D", .12)
        mock_run_local_cmd.return_value = response
        self.assertTrue(process.is_pid_running("1234"))

    @patch('nssutils.lib.shell.run_local_cmd')
    def test_is_pid_running_returns_true_with_R_in_response(self, mock_run_local_cmd):
        response = shell.Response(1, "R", .12)
        mock_run_local_cmd.return_value = response
        self.assertTrue(process.is_pid_running("1234"))

    @patch('nssutils.lib.shell.run_local_cmd')
    def test_is_pid_running_returns_true_with_S_in_response(self, mock_run_local_cmd):
        response = shell.Response(1, "S", .12)
        mock_run_local_cmd.return_value = response
        self.assertTrue(process.is_pid_running("1234"))

    @patch('nssutils.lib.shell.run_local_cmd')
    def test_is_pid_running_returns_true_with_T_in_response(self, mock_run_local_cmd):
        response = shell.Response(1, "T", .12)
        mock_run_local_cmd.return_value = response
        self.assertTrue(process.is_pid_running("1234"))

    @patch('nssutils.lib.shell.run_local_cmd')
    def test_is_pid_running_returns_false_with_invalid_response(self, mock_run_local_cmd):
        response = shell.Response(1, "A", .12)
        mock_run_local_cmd.return_value = response
        self.assertFalse(process.is_pid_running("1234"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_is_pid_running_on_remote_host_returns_true_with_D_in_response_and_password_is_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "D", .234)
        self.assertTrue(process.is_pid_running_on_remote_host("1234", "root", "admin"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_is_pid_running_on_remote_host_returns_true_with_R_in_response_and_password_is_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "R", .234)
        self.assertTrue(process.is_pid_running_on_remote_host("1234", "root", "admin"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_is_pid_running_on_remote_host_returns_true_with_S_in_response_and_password_is_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "S", .234)
        self.assertTrue(process.is_pid_running_on_remote_host("1234", "root", "admin"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_is_pid_running_on_remote_host_returns_true_with_T_in_response_and_password_is_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "T", .234)
        self.assertTrue(process.is_pid_running_on_remote_host("1234", "root", "admin"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_is_pid_running_on_remote_host_returns_false_with_invalid_response_and_password_is_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "A", .234)
        self.assertFalse(process.is_pid_running_on_remote_host("1234", "root", "admin"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_is_pid_running_on_remote_host_returns_true_with_D_in_response_and_password_is_not_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "D", .234)
        self.assertTrue(process.is_pid_running_on_remote_host("1234", "root", "admin", "password"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_is_pid_running_on_remote_host_returns_true_with_R_in_response_and_password_is_not_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "R", .234)
        self.assertTrue(process.is_pid_running_on_remote_host("1234", "root", "admin", "password"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_is_pid_running_on_remote_host_returns_true_with_S_in_response_and_password_is_not_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "S", .234)
        self.assertTrue(process.is_pid_running_on_remote_host("1234", "root", "admin", "password"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_is_pid_running_on_remote_host_returns_true_with_T_in_response_and_password_is_not_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "T", .234)
        self.assertTrue(process.is_pid_running_on_remote_host("1234", "root", "admin", "password"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_is_pid_running_on_remote_host_returns_false_with_invalid_response_and_password_is_not_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "A", .234)
        self.assertFalse(process.is_pid_running_on_remote_host("1234", "root", "admin", "password"))

    @patch("nssutils.lib.process.is_pid_running")
    @patch("os.getpgid")
    @patch("os.killpg")
    def test_kill_pid_returns_false_if_pid_is_running(self, mock_os_killpg, mock_os_getpid, mock_is_pid_running):
        mock_os_killpg.return_value = None
        mock_os_getpid.return_value = None
        mock_is_pid_running.return_value = True
        self.assertFalse(process.kill_pid("999"))

    @patch('nssutils.lib.shell.run_local_cmd')
    @patch("os.getpgid")
    @patch("os.killpg")
    def test_kill_pid_returns_true_if_pid_is_not_running(self, mock_os_killpg, mock_os_getpid, mock_run_local_cmd):
        mock_os_killpg.return_value = None
        mock_os_getpid.return_value = None
        response = shell.Response(1, "A", .12)
        mock_run_local_cmd.return_value = response
        self.assertTrue(process.kill_pid("1199"))


if __name__ == "__main__":
    unittest2.main(verbosity=2)
