#!/usr/bin/env python
import unittest2

from nssutils.lib import shell
from nssutils.tests import func_test_utils, test_fixture
from nssutils.tests.func_test_utils import func_dec


class LocalShellAcceptanceTests(unittest2.TestCase):

    command_timeout_rc = 177

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

    @func_dec("Shell Library", "Successful local command execution produces return code 0")
    def test_successful_local_command_produces_return_code_zero(self):
        cmd = shell.Command("hostname")
        resp = shell.run_local_cmd(cmd)
        self.assertGreater(float(resp.elapsed_time), 0)
        self.assertEqual(0, resp.rc)

    @func_dec("Shell Library", "Unsuccessful local command execution produces non-zero return code")
    def test_unsuccessful_local_command_produces_non_zero_return_code(self):
        cmd = shell.Command("adfasdfasdfadadfasdfasda")
        resp = shell.run_local_cmd(cmd)
        self.assertNotEqual(0, resp.rc)

    @func_dec("Shell Library", "Local command execution exceeding timeout is forcibly terminated")
    def test_local_command_exceeding_timeout_is_terminated(self):
        cmd = shell.Command("sleep 1", timeout=.1)
        resp = shell.run_local_cmd(cmd)
        self.assertEqual(self.command_timeout_rc, resp.rc)


if __name__ == "__main__":
    unittest2.main(verbosity=2)
