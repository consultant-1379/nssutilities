#!/usr/bin/env python
import copy
from random import choice

import unittest2

from nssutils.lib import filesystem, shell, thread_queue
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

    @func_dec("Shell Library", "Run remote command that produces extra large output")
    def test_running_remote_command_producing_large_response(self):
        cmd = shell.Command("tail -10000 /var/log/dracut.log", timeout=60)
        resp = shell.run_remote_cmd(cmd, REMOTE_TEST_HOST, REMOTE_TEST_USER)
        self.assertEqual(0, resp.rc)

    @func_dec("Shell Library", "Large number of threads can share small number of connections in connection pool")
    def test_large_number_of_threads_can_share_connections_via_connection_pool(self):
        cmd = shell.Command("hostname", timeout=10)

        # Figure out the remote hostname, for reference
        hostname = shell.run_remote_cmd(cmd, REMOTE_TEST_HOST, REMOTE_TEST_USER).stdout

        def worker(cmd):
            return shell.run_remote_cmd(cmd, REMOTE_TEST_HOST, REMOTE_TEST_USER)

        shell.MAX_CONNECTIONS_PER_REMOTE_HOST = 3
        work_items = [copy.copy(cmd) for _ in range(0, 50)]
        tq = thread_queue.ThreadQueue(work_items, 10, worker)
        tq.execute()

        num_matches = 0

        for work_item in tq.work_entries:
            if work_item.result is not None and work_item.result.stdout is not None and work_item.result.stdout == hostname:
                num_matches += 1

        self.assertEqual(50, num_matches)

    @func_dec("Shell Library", "Test files can be uploaded and downloaded from remote host")
    def test_file_can_uploaded_and_then_downloaded_from_remote_host(self):
        local_file_path = "/tmp/local_shell_upload_download_test_file.txt"
        remote_file_path = "/tmp/remote_shell_upload_download_test_file.txt"

        # Create the local test file, overwriting it if it exists
        filesystem.write_data_to_file("THIS\nIS\nA\nTEST\nFILE", local_file_path)

        # Remove the remote file if it exists
        if filesystem.does_remote_file_exist(remote_file_path, REMOTE_TEST_HOST, REMOTE_TEST_USER):
            filesystem.delete_remote_file(remote_file_path, REMOTE_TEST_HOST, REMOTE_TEST_USER)

        # Upload the test file
        shell.upload_file(local_file_path, remote_file_path, REMOTE_TEST_HOST, REMOTE_TEST_USER)

        # Assert that the file exists on the remote host
        self.assertTrue(filesystem.does_remote_file_exist(remote_file_path, REMOTE_TEST_HOST, REMOTE_TEST_USER))

        # Delete the local file
        filesystem.delete_file(local_file_path)
        self.assertFalse(filesystem.does_file_exist(local_file_path))

        # Download the file from the remote host
        shell.download_file(remote_file_path, local_file_path, REMOTE_TEST_HOST, REMOTE_TEST_USER)
        self.assertTrue(filesystem.does_file_exist(local_file_path))

        # Delete the local and remote test files
        filesystem.delete_file(local_file_path)
        filesystem.delete_remote_file(remote_file_path, REMOTE_TEST_HOST, REMOTE_TEST_USER)

    @func_dec("Shell Library", "Execute commands on a remote host as different users")
    def test_successful_remote_command_with_different_users(self):
        cmd = shell.Command("whoami", timeout=10)
        resp = shell.run_remote_cmd(cmd, "netsim", "netsim", "netsim")
        self.assertEqual("netsim", resp.stdout.strip())

        resp = shell.run_remote_cmd(cmd, "netsim", "root", "shroot")
        self.assertEqual("root", resp.stdout.strip())

    @func_dec("Shell Library", "Execute commands on a remote host as different users")
    def test_successful_remote_command_with_different_users_when_pool_is_full(self):
        shell.MAX_CONNECTIONS_PER_REMOTE_HOST = 1
        cmd = shell.Command("whoami", timeout=10)
        resp = shell.run_remote_cmd(cmd, "netsim", "netsim", "netsim")
        self.assertEqual("netsim", resp.stdout.strip())

        resp = shell.run_remote_cmd(cmd, "netsim", "root", "shroot")
        self.assertEqual("root", resp.stdout.strip())

    @func_dec("Shell Library", "Execute commands on a remote host as different users")
    def test_successful_remote_command_with_different_users_when_pool_is_full_and_needs_to_wait_for_available_connection(self):
        shell.MAX_CONNECTIONS_PER_REMOTE_HOST = 5
        cmd = shell.Command("sleep 2", timeout=11)

        def worker(cmd):
            user = [('netsim', 'netsim')] * 10
            user.append(('root', 'shroot'))
            return shell.run_remote_cmd(cmd, 'netsim', *choice(user))

        work_items = [copy.copy(cmd) for _ in range(0, 10)]
        tq = thread_queue.ThreadQueue(work_items, 5, worker)
        tq.execute()

        cmd = shell.Command("whoami", timeout=10)
        resp = shell.run_remote_cmd(cmd, "netsim", "root", "shroot")
        self.assertEqual("root", resp.stdout.strip())


if __name__ == "__main__":
    unittest2.main(verbosity=2)
