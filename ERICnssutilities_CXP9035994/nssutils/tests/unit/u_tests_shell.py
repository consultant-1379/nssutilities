#!/usr/bin/env python
import Queue
import collections
import errno

import unittest2
from mock import Mock, patch

from nssutils.lib import shell
from nssutils.lib.exceptions import ShellCommandReturnedNonZero
from nssutils.tests import unit_test_utils


class ShellUnitTests(unittest2.TestCase):

    command_timeout_rc = 177
    command_connection_closed_rc = 255

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    @patch('nssutils.lib.shell.is_host_pingable', return_value=True)
    @patch('nssutils.lib.config.is_a_cloud_deployment', return_value=True)
    @patch('nssutils.lib.shell.RemoteExecutor')
    @patch('nssutils.lib.shell.ConnectionPoolManager')
    def test_run_remote_cmd_pings_a_cloud_host_keeping_the_connection_open_and_returns_a_successful_response(self, *_):
        self.assertTrue(shell.run_remote_cmd("Successful command", "Valid host", "Valid user", password="netsim", ping_host=True))
        shell.connection_mgr = None

    @patch('nssutils.lib.shell.is_host_pingable', return_value=False)
    @patch('nssutils.lib.config.is_a_cloud_deployment')
    def test_run_remote_cmd_returns_instantly_a_response_when_the_host_is_not_pingable(
            self, mock_is_a_cloud_deployment, *_):
        cmd = shell.Command("Successful command")
        self.assertTrue(shell.run_remote_cmd(cmd, "host", "user", ping_host=True))
        self.assertFalse(mock_is_a_cloud_deployment.called)

    @patch('nssutils.lib.shell.is_host_pingable', return_value=True)
    @patch('nssutils.lib.config.is_a_cloud_deployment', return_value=False)
    @patch('nssutils.lib.shell.RemoteExecutor')
    @patch('nssutils.lib.shell.ConnectionPoolManager')
    def test_run_remote_cmd_returns_a_successful_response_on_a_physical_deployment(self, *_):
        cmd = shell.Command("Successful command")
        self.assertTrue(shell.run_remote_cmd(cmd, "Valid host", "Valid user"))
        shell.connection_mgr = None

    @patch("nssutils.lib.mutexer.mutex")
    @patch("nssutils.lib.log.logger.debug")
    def test_return_connection_successfully_closes_the_connection_if_the_host_is_not_in_the_remote_connection_pool(self, *_):
        host = "host"
        connection = Mock()
        conn_pool_mgr = shell.ConnectionPoolManager()
        conn_pool_mgr.remote_connection_pool["host1"] = {}

        conn_pool_mgr.return_connection(host, connection)

        self.assertTrue(connection.close.called)

    @patch("nssutils.lib.mutexer.mutex")
    @patch("nssutils.lib.log.logger.debug")
    def test_return_connection_logs_an_error_if_theres_an_issue_closing_the_connection(self, mock_log, _):
        host = "host"
        connection = Mock()
        conn_pool_mgr = shell.ConnectionPoolManager()
        conn_pool_mgr.remote_connection_pool[host] = {}
        conn_pool_mgr.remote_connection_pool[host]['available'] = Mock()
        conn_pool_mgr.remote_connection_pool[host]['used'] = Mock()
        connection.close.side_effect = Exception

        conn_pool_mgr.return_connection(host, connection)

        self.assertTrue(mock_log.called)

    @patch("nssutils.lib.log.logger.debug")
    @patch("nssutils.lib.mutexer.mutex")
    def test_return_connection_closes_the_connection_if_theres_an_issue_with_removing_the_connection_from_the_used_queue(self, *_):
        host = "host"
        connection = Mock()
        conn_pool_mgr = shell.ConnectionPoolManager()
        conn_pool_mgr.remote_connection_pool[host] = {}
        conn_pool_mgr.remote_connection_pool[host]['available'] = Mock()
        used = conn_pool_mgr.remote_connection_pool[host]['used'] = Mock()
        used.remove.side_effect = ValueError

        conn_pool_mgr.return_connection(host, connection)

        self.assertTrue(connection.close.called)

    @patch("nssutils.lib.log.logger.debug")
    @patch("nssutils.lib.mutexer.mutex")
    def test_return_connection_closes_the_connection_if_the_connection_does_not_need_to_be_kept_open(self, *_):
        host = "host"
        connection = Mock()
        conn_pool_mgr = shell.ConnectionPoolManager()
        conn_pool_mgr.remote_connection_pool[host] = {}
        conn_pool_mgr.remote_connection_pool[host]['available'] = Mock()
        conn_pool_mgr.remote_connection_pool[host]['used'] = collections.deque([connection])

        conn_pool_mgr.return_connection(host, connection)

        self.assertTrue(connection.close.called)
        self.assertEqual(0, len(conn_pool_mgr.remote_connection_pool[host]['used']))

    @patch("nssutils.lib.log.logger.debug")
    @patch("nssutils.lib.mutexer.mutex")
    def test_return_connection_removes_an_invalid_connection_from_the_used_queue_and_closes_the_connection_even_if_the_connection_needed_to_be_kept_open(self, *_):
        host = "host"
        connection1 = Mock()
        connection1.get_transport().is_authenticated.return_value = False
        connection2 = Mock()
        conn_pool_mgr = shell.ConnectionPoolManager()
        conn_pool_mgr.remote_connection_pool[host] = {}
        conn_pool_mgr.remote_connection_pool[host]['available'] = Queue.Queue(shell.MAX_CONNECTIONS_PER_REMOTE_HOST)
        conn_pool_mgr.remote_connection_pool[host]['used'] = collections.deque([connection1, connection2])

        conn_pool_mgr.return_connection(host, connection1, keep_connection_open=True)

        self.assertTrue(connection1.close.called)
        self.assertEqual(1, len(conn_pool_mgr.remote_connection_pool[host]['used']))

    @patch("nssutils.lib.log.logger.debug")
    @patch("nssutils.lib.mutexer.mutex")
    def test_return_connection_removes_a_valid_connection_from_the_used_queue_and_closes_the_connection_when_the_available_queue_is_full(self, *_):
        host = "host"
        connection1 = Mock()
        connection1.get_transport().is_authenticated.return_value = True
        connection2 = Mock()
        conn_pool_mgr = shell.ConnectionPoolManager()
        conn_pool_mgr.remote_connection_pool[host] = {}
        available = conn_pool_mgr.remote_connection_pool[host]['available'] = Mock()
        available.put.side_effect = Queue.Full
        conn_pool_mgr.remote_connection_pool[host]['used'] = collections.deque([connection1, connection2])

        conn_pool_mgr.return_connection(host, connection1, keep_connection_open=True)

        self.assertTrue(connection1.close.called)
        self.assertEqual(1, len(conn_pool_mgr.remote_connection_pool[host]['used']))

    @patch("nssutils.lib.log.logger.debug")
    @patch("nssutils.lib.mutexer.mutex")
    def test_return_connection_removes_a_valid_connection_from_the_used_queue_and_adds_it_to_the_available_when_the_connection_needs_to_be_kept_open(self, *_):
        host = "host"
        connection1 = Mock()
        connection1.get_transport().is_authenticated.return_value = True
        connection2 = Mock()
        conn_pool_mgr = shell.ConnectionPoolManager()
        conn_pool_mgr.remote_connection_pool[host] = {}
        conn_pool_mgr.remote_connection_pool[host]['available'] = Queue.Queue(shell.MAX_CONNECTIONS_PER_REMOTE_HOST)
        conn_pool_mgr.remote_connection_pool[host]['used'] = collections.deque([connection1, connection2])

        conn_pool_mgr.return_connection(host, connection1, keep_connection_open=True)
        self.assertEqual(1, conn_pool_mgr.remote_connection_pool[host]['available'].qsize())
        self.assertEqual(1, len(conn_pool_mgr.remote_connection_pool[host]['used']))

    def test_response_attributes_cant_be_set_directly(self):
        response = shell.Response()
        response._rc = 4

        try:
            response.rc = 5
            self.fail("Direct modification of Response instance attribute should have produced an AttributeError, but didn't")
        except AttributeError:
            pass

    def test_command_instantiation_initializes_blank_response(self):
        command = shell.Command("test command")
        command._set_attributes()
        self.assertIsNotNone(command.response)
        self.assertIsNone(command.response.rc)
        self.assertIsNone(command.response.stdout)
        self.assertIsNone(command.response.elapsed_time)

    def test_reinitializing_command_attributes_creates_new_response(self):
        command = shell.Command("test command")
        command._set_attributes()
        initial_id = id(command.response)
        command._set_attributes()
        self.assertNotEqual(initial_id, id(command.response))

    def test_second_execution_of_command_uses_higher_timeout_than_first_execution(self):
        command = shell.Command("test command")
        command.initialize_attributes()
        command.pre_execute()
        initial_timeout = command.current_timeout
        command.retry_count = 2
        command.pre_execute()
        second_timeout = command.current_timeout
        self.assertGreater(second_timeout, initial_timeout)

    def test_successful_local_command_execution_sets_rc_and_stdout_in_response(self):
        command = shell.Command("dir")
        response = shell.LocalExecutor(command).execute()
        self.assertIsNotNone(response.rc)
        self.assertIsNotNone(response.stdout)

    def test_local_command_is_killed_if_timeout_exceeded(self):
        command = shell.Command("sleep 1", timeout=.2, allow_retries=False)
        response = shell.LocalExecutor(command).execute()
        self.assertEqual(response.rc, self.command_timeout_rc)

    def test_local_command_execution_produces_runtime_error_if_configured_to_assert_pass(self):
        command = shell.Command("asdfasdfasdafasdfa", check_pass=True)
        executor = shell.LocalExecutor(command)
        self.assertRaises(RuntimeError, executor.execute)

    @patch("nssutils.lib.shell.Command._sleep_between_attempts")
    def test_sleep_between_local_command_executions(self, mock_sleep_between_attempts):
        command = shell.Command("dir")
        command.initialize_attributes()
        command.pre_execute()
        command.response._rc = self.command_connection_closed_rc
        command.response._stdout = "FAIL"
        command.response._elapsed_time = .0021
        self.assertFalse(mock_sleep_between_attempts.called)
        command.post_execute()
        self.assertTrue(mock_sleep_between_attempts.called)

    def test_local_command_timeout_is_configured_for_retry(self):
        command = shell.Command("dir")
        command.initialize_attributes()
        command.pre_execute()
        command.response._rc = self.command_connection_closed_rc
        command.response._stdout = "FAIL"
        command.response._elapsed_time = .0021
        command.post_execute()
        self.assertFalse(command.finished)

    @patch("nssutils.lib.log.logger.debug")
    @patch('nssutils.lib.shell.ConnectionPoolManager')
    def test_are_ssh_credentails_valid_returns_true_if_connection_is_valid(self, mock_connection_pool_manager, _):
        shell.delete_connection_mgr()
        mock_connection_pool_manager.return_value = Mock()
        mock_connection_pool_manager._establish_connection.return_value = Mock()
        self.assertTrue(shell.are_ssh_credentials_valid("host", "user"))
        shell.delete_connection_mgr()

    @patch("nssutils.lib.log.logger.debug")
    @patch('nssutils.lib.shell.ConnectionPoolManager')
    def test_are_ssh_credentails_valid_returns_false_if_connection_cant_be_established(self, mock_connection_pool_manager, _):
        shell.delete_connection_mgr()
        mock_connection_pool_manager.return_value = Mock()
        mock_connection_pool_manager.side_effect = RuntimeError("Couldn't create connection")
        self.assertFalse(shell.are_ssh_credentials_valid("host", "user"))
        shell.delete_connection_mgr()

    @patch("nssutils.lib.shell.ConnectionPoolManager._establish_connection")
    def test_request_for_connection_prompts_connection_creation_when_pool_is_empty(self, mock_connection_pool_manager):
        conn_mgr = shell.ConnectionPoolManager()
        conn_mgr.get_connection("foo", "bar")
        self.assertTrue(mock_connection_pool_manager.called)

    @patch("nssutils.lib.shell.ConnectionPoolManager._establish_connection")
    def test_first_request_for_connection_for_host_creates_entries_in_connection_pool_dict(self, _):
        conn_mgr = shell.ConnectionPoolManager()
        self.assertFalse("foo" in conn_mgr.remote_connection_pool)
        conn_mgr.get_connection("foo", "bar")
        self.assertTrue("foo" in conn_mgr.remote_connection_pool)
        self.assertTrue("available" in conn_mgr.remote_connection_pool["foo"])
        self.assertTrue("used" in conn_mgr.remote_connection_pool["foo"])

    @patch("nssutils.lib.shell.ConnectionPoolManager.is_connected")
    @patch("nssutils.lib.shell.ConnectionPoolManager._establish_connection")
    def test_newly_created_connections_are_added_to_used_list(self, mock_establish_connection, mock_is_connected):
        fake_connection = object()
        mock_is_connected.return_value = True
        mock_establish_connection.return_value = fake_connection
        conn_mgr = shell.ConnectionPoolManager()
        conn_mgr.get_connection("foo", "bar")

        # This will generate a ValueError if fake_connection is not in the used deque
        conn_mgr.remote_connection_pool["foo"]["used"].remove(fake_connection)

    @patch("nssutils.lib.shell.ConnectionPoolManager.is_connected")
    @patch("Queue.Queue.get")
    def test_nonetype_connection_returned_if_queues_are_full_and_no_connections_available(self, mock_queue_get, mock_is_connected):
        mock_queue_get.side_effect = Queue.Empty()
        mock_is_connected.return_value = True
        host = "test-host"

        # Initialize the queues and fill up the used queue
        conn_mgr = shell.ConnectionPoolManager()
        conn_mgr.remote_connection_pool[host] = {}
        conn_mgr.remote_connection_pool[host]['available'] = Queue.Queue(shell.MAX_CONNECTIONS_PER_REMOTE_HOST)
        conn_mgr.remote_connection_pool[host]['used'] = collections.deque(xrange(1, shell.MAX_CONNECTIONS_PER_REMOTE_HOST + 1))

        self.assertIsNone(conn_mgr.get_connection(host, "blah"))

    @patch("nssutils.lib.shell.ConnectionPoolManager.is_connected")
    def test_connections_removed_from_available_queue_and_added_to_used_queue_when_requested(self, mock_is_connected):
        host = "test-host"
        connection1 = object()
        connection2 = object()
        mock_is_connected.return_value = True

        # Initialize the queues and add a couple of connections to the available queue
        conn_mgr = shell.ConnectionPoolManager()
        conn_mgr.remote_connection_pool[host] = {}
        conn_mgr.remote_connection_pool[host]['available'] = Queue.Queue(shell.MAX_CONNECTIONS_PER_REMOTE_HOST)
        conn_mgr.remote_connection_pool[host]['available'].put(connection1)
        conn_mgr.remote_connection_pool[host]['available'].put(connection2)
        conn_mgr.remote_connection_pool[host]['used'] = collections.deque()

        self.assertEqual(connection1, conn_mgr.get_connection(host, "blah"))
        self.assertEqual(connection2, conn_mgr.get_connection(host, "blah"))
        self.assertEqual(0, conn_mgr.remote_connection_pool[host]['available'].qsize())

        # These removes will fail if the objects aren't in the used deque
        conn_mgr.remote_connection_pool[host]['used'].remove(connection1)
        conn_mgr.remote_connection_pool[host]['used'].remove(connection2)

    @patch('nssutils.lib.cache.get_ms_host')
    def test_run_on_ms_failing_to_ping_host_returns_rc_5(self, mock_get_ms_host):
        mock_get_ms_host.return_value = "Not a pingable host"
        cmd = shell.Command('ls -l')
        resp = shell.run_cmd_on_ms(cmd)
        self.assertEqual(5, resp.rc)

    @patch('nssutils.lib.shell.run_local_cmd')
    @patch('nssutils.lib.cache.get_ms_host')
    def test_run_on_ms_none_type_host_defaults_to_run_local(self, mock_get_ms_host, mock_run_local_cmd):
        mock_get_ms_host.return_value = None
        cmd = shell.Command('ls -l')
        shell.run_cmd_on_ms(cmd)
        self.assertTrue(mock_run_local_cmd.called)

    @patch('nssutils.lib.shell.run_cmd_on_ms')
    @patch('nssutils.lib.cache.get_ms_host')
    @patch('nssutils.lib.cache.get_vnf_laf')
    def test_run_cmd_on_vnf_none_type_host_defaults_to_run_on_ms(self, mock_get_vnf_laf, mock_get_ms_host,
                                                                 mock_run_cmd_on_ms):
        mock_get_vnf_laf.return_value = None
        mock_get_ms_host.return_value = '1.2.3.4'
        cmd = shell.Command('ls -l')
        shell.run_cmd_on_vnf(cmd)
        self.assertTrue(mock_run_cmd_on_ms.called)

    @patch('nssutils.lib.shell.run_local_cmd')
    @patch('nssutils.lib.cache.get_ms_host')
    @patch('nssutils.lib.cache.get_vnf_laf')
    def test_run_cmd_on_vnf_none_type_host_defaults_to_run_local(self, mock_get_vnf_laf, mock_get_ms_host,
                                                                 mock_run_local_cmd):
        mock_get_vnf_laf.return_value = None
        mock_get_ms_host.return_value = None
        cmd = shell.Command('ls -l')
        shell.run_cmd_on_vnf(cmd)
        self.assertTrue(mock_run_local_cmd.called)

    @patch('nssutils.lib.shell.run_remote_cmd')
    @patch('nssutils.lib.cache.get_vnf_laf_credentials')
    @patch('nssutils.lib.cache.get_vnf_laf')
    def test_run_cmd_on_vnf_retrieves_vnf_credentials(self, mock_get_vnf_laf, mock_get_vnf_laf_credentials,
                                                      mock_run_remote_cmd):
        mock_get_vnf_laf.return_value = '1.2.3.4'
        cmd = shell.Command('ls -l')
        mock_get_vnf_laf_credentials.return_value = ('user', 'password')
        mock_run_remote_cmd.return_value = shell.Response(rc=0, stdout="Success")
        response = shell.run_cmd_on_vnf(cmd)
        self.assertTrue(mock_get_vnf_laf_credentials.called)
        self.assertEqual(shell.Response, type(response))

    @patch('nssutils.lib.shell.run_cmd_on_vm')
    def test_change_deployment_file_permissions_raises_exception(self, mock_run_cmd_on_vm):
        mock_run_cmd_on_vm.return_value = shell.Response(rc=2, stdout='Error')
        self.assertRaises(ShellCommandReturnedNonZero, shell.change_deployment_file_permissions, '', '', '1.2.3.4')

    @patch('nssutils.lib.shell.run_cmd_on_vm')
    def test_change_deployment_file_permissions(self, mock_run_cmd_on_vm):
        mock_run_cmd_on_vm.return_value = shell.Response(rc=0, stdout='Success')
        try:
            shell.change_deployment_file_permissions('', '', '1.2.3.4')
        except ShellCommandReturnedNonZero:
            self.fail("Failed to change file permissions.")

    @patch('nssutils.lib.shell.ConnectionPoolManager')
    def test_sftp_path_exists_returns_true_when_given_valid_details(self, mock_connection_pool_manager):
        mock_connection_pool_manager.return_value = Mock()
        mock_connection_pool_manager.get_connection.return_value = Mock()
        mock_connection_pool_manager.open_sftp.return_value = Mock()
        mock_connection_pool_manager.sftp_client.stat.return_value = Mock()
        self.assertTrue(shell.sftp_path_exists("/path/to/file", "hostname", "user"))

    @patch("nssutils.lib.shell.ConnectionPoolManager.get_connection")
    def test_sftp_path_exists_returns_false(self, mock_get_connection):
        shell.delete_connection_mgr()
        mock_get_connection.return_value = Mock(sftp_client=Mock(stat=Mock(side_effect=IOError(errno.ENOENT, "File not found"))))
        self.assertFalse(shell.sftp_path_exists("/path/to/file", "hostname", "user", "password"))
        shell.delete_connection_mgr()

    @patch('nssutils.lib.shell.run_remote_cmd_with_ms_proxy')
    @patch('nssutils.lib.config.is_a_cloud_deployment', return_value=True)
    @patch('nssutils.lib.cache.copy_cloud_user_ssh_private_key_file_to_emp')
    def test_run_cmd_on_vm_copies_emp_key_file_on_cloud(self, mock_emp_key_file, *_):
        shell.run_cmd_on_vm("command", "vm")
        self.assertTrue(mock_emp_key_file.called)

    @patch('nssutils.lib.shell.run_remote_cmd_with_ms_proxy')
    @patch('nssutils.lib.config.is_a_cloud_deployment', return_value=False)
    @patch('nssutils.lib.cache.copy_cloud_user_ssh_private_key_file_to_emp')
    def test_run_cmd_on_vm_does_not_call_copy_emp_key_file_when_not_on_cloud(self, mock_emp_key_file, *_):
        shell.run_cmd_on_vm("command", "vm")
        self.assertFalse(mock_emp_key_file.called)


if __name__ == "__main__":
    unittest2.main(verbosity=2)
