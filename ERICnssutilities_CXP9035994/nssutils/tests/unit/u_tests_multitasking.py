#!/usr/bin/env python
import time

import unittest2
from mock import Mock, patch

from nssutils.lib import multitasking
from nssutils.tests import unit_test_utils


def good_func(interval):
    time.sleep(interval)


def bad_func():
    time.sleep(.001)


class MultitaskingUnitTests(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    def _sleeper(self, interval):
        time.sleep(interval)

    def _exception_raiser(self):
        return 1 / 0

    def _custom_exception_raiser(self):
        raise RuntimeError("This is a test message")

    def test_thread_raises_exception(self):
        thread = multitasking.UtilitiesThread(None, self._exception_raiser, None)
        thread.start()
        time.sleep(.1)
        self.assertTrue(thread.has_raised_exception())

    def test_thread_exception_message_is_correct(self):
        thread = multitasking.UtilitiesThread(None, self._custom_exception_raiser, None)
        thread.start()
        time.sleep(.1)
        self.assertTrue(thread.has_raised_exception())
        self.assertEquals("This is a test message", thread.get_exception_msg())

    def test_waiting_for_threads_to_finish(self):
        thread1 = multitasking.UtilitiesThread(None, self._sleeper, None, [.2])
        thread2 = multitasking.UtilitiesThread(None, self._sleeper, None, [.4])
        thread_list = [thread1, thread2]
        thread1.start()
        thread2.start()
        multitasking.wait_for_tasks_to_finish(thread_list)
        self.assertFalse(thread1.is_alive())
        self.assertFalse(thread2.is_alive())

    def test_exception_raised_in_thread_is_raised_on_main_thread(self):
        thread = multitasking.UtilitiesThread(None, self._custom_exception_raiser, None)
        thread_list = [thread]
        self.assertFalse(thread.has_raised_exception())
        thread.start()
        self._sleeper(.1)
        multitasking.wait_for_tasks_to_finish(thread_list, timeout=1)
        self.assertTrue(thread.has_raised_exception())

    def test_invoking_terminate_threads_signals_that_threads_should_finish(self):
        thread = multitasking.UtilitiesThread(None, self._sleeper, None, [.5])
        self.assertFalse(multitasking.should_workers_exit())
        thread.start()
        self.assertFalse(multitasking.should_workers_exit())
        multitasking.terminate_threads()

    def test_invoking_wait_for_threads_to_finish_with_no_registered_threads_does_nothing(self):
        multitasking.wait_for_tasks_to_finish([])

    @patch('time.sleep', return_value=0)
    @patch('nssutils.lib.multitasking.process.is_pid_running', side_effect=[True, True, False])
    @patch('nssutils.lib.multitasking.UtilitiesExternalDaemon.get_pid', return_value=True)
    @patch('nssutils.lib.multitasking.UtilitiesExternalDaemon.delete_pid_file')
    @patch('nssutils.lib.multitasking.UtilitiesExternalDaemon._raise_if_running', return_value=None)
    @patch('subprocess.Popen')
    @patch('nssutils.lib.multitasking.process.kill_pid')
    @patch('nssutils.lib.multitasking.UtilitiesExternalDaemon.write_pid_file')
    def test_starting_and_stopping_external_daemon_removes_process(self, mock_write_pid, mock_kill_pid, *_):
        daemon = multitasking.UtilitiesExternalDaemon("test-daemon", ["/bin/bash", "-c", "sleep", "100"])
        daemon.start()
        self.assertTrue(mock_write_pid.called)
        daemon.stop()
        self.assertTrue(mock_kill_pid.called)

    @patch('time.sleep', return_value=0)
    @patch('nssutils.lib.multitasking.process.is_pid_running', side_effect=[True, False])
    @patch('nssutils.lib.multitasking.UtilitiesExternalDaemon.get_pid', return_value=True)
    @patch('nssutils.lib.multitasking.UtilitiesExternalDaemon.delete_pid_file')
    def test_pid_file_is_removed_when_external_daemon_is_stopped(self, mock_delete_pid_file, *_):
        daemon = multitasking.UtilitiesExternalDaemon("test-daemon2", ["sleep", "100"])
        daemon.stop()
        self.assertTrue(mock_delete_pid_file.called)

    @patch('nssutils.lib.multitasking.process.is_pid_running', return_value=False)
    @patch('nssutils.lib.multitasking.UtilitiesExternalDaemon.get_pid', return_value=True)
    @patch('nssutils.lib.multitasking.UtilitiesExternalDaemon.delete_pid_file')
    def test_everything_cleaned_up_if_external_daemon_killed_externally_before_stop(self, mock_delete_pid_file, *_):
        daemon = multitasking.UtilitiesExternalDaemon("test-daemon3", ["sleep", "100"])
        daemon.stop()
        self.assertTrue(mock_delete_pid_file.called)

    @patch('nssutils.lib.multitasking.AbstractUtilitiesDaemon.__init__', return_value=None)
    def test_creating_external_daemon_with_nonetype_cmd_raises_value_error(self, *_):
        self.assertRaises(ValueError, multitasking.UtilitiesExternalDaemon, "test-daemon4", None)

    @patch('nssutils.lib.multitasking.AbstractUtilitiesDaemon.__init__', return_value=None)
    def test_creating_external_daemon_with_empty_cmd_raises_value_error(self, *_):
        self.assertRaises(ValueError, multitasking.UtilitiesExternalDaemon, "test-daemon5", "")

    @patch('nssutils.lib.multitasking.AbstractUtilitiesDaemon.__init__', return_value=None)
    @patch('nssutils.lib.multitasking.UtilitiesExternalDaemon._raise_if_running', side_effect=RuntimeError("Error"))
    def test_creating_the_same_external_daemon_twice_raises_runtime_error(self, *_):
        daemon2 = multitasking.UtilitiesExternalDaemon("test-daemon6", ["sleep", "60"])
        self.assertRaises(RuntimeError, daemon2.start)

    @patch('time.sleep', return_value=0)
    @patch('nssutils.lib.multitasking.process.is_pid_running', side_effect=[True, True, False])
    @patch('nssutils.lib.multitasking.UtilitiesDaemon.get_pid', return_value=True)
    @patch('nssutils.lib.multitasking.UtilitiesDaemon.delete_pid_file')
    @patch('nssutils.lib.multitasking.UtilitiesDaemon._raise_if_running', return_value=None)
    @patch('subprocess.Popen')
    @patch('nssutils.lib.multitasking.UtilitiesDaemon.write_pid_file')
    @patch('nssutils.lib.multitasking.process.kill_pid')
    def test_starting_and_stopping_daemon_removes_process(self, mock_kill_pid, mock_write_pid, *_):
        daemon = multitasking.UtilitiesDaemon("test-daemon7", good_func, [20])
        daemon.start()
        self.assertTrue(mock_write_pid.called)
        daemon.stop()
        self.assertTrue(mock_kill_pid.called)

    @patch('time.sleep', return_value=0)
    @patch('nssutils.lib.multitasking.process.is_pid_running', side_effect=[True, False])
    @patch('nssutils.lib.multitasking.UtilitiesDaemon.get_pid', return_value=True)
    @patch('nssutils.lib.multitasking.UtilitiesDaemon.delete_pid_file')
    def test_pid_file_is_removed_when_daemon_is_stopped(self, mock_delete_pid_file, *_):
        daemon = multitasking.UtilitiesDaemon("test-daemon8", good_func, [20])
        daemon.stop()
        self.assertTrue(mock_delete_pid_file.called)

    @patch('nssutils.lib.multitasking.process.is_pid_running', return_value=False)
    @patch('nssutils.lib.multitasking.UtilitiesDaemon.get_pid', return_value=True)
    @patch('nssutils.lib.multitasking.UtilitiesDaemon.delete_pid_file')
    def test_everything_cleaned_up_if_daemon_killed_externally_before_stop(self, mock_delete_pid_file, *_):
        daemon = multitasking.UtilitiesDaemon("test-daemon9", good_func, [20])
        daemon.stop()
        self.assertTrue(mock_delete_pid_file.called)

    @patch('nssutils.lib.multitasking.AbstractUtilitiesDaemon.__init__', return_value=None)
    def test_creating_daemon_with_nonetype_func_reference_raises_value_error(self, *_):
        self.assertRaises(ValueError, multitasking.UtilitiesDaemon, "test-daemon", None)

    @patch('time.sleep', return_value=0)
    @patch('threading.Thread.__init__')
    @patch('nssutils.lib.multitasking.log.log_entry')
    @patch('datetime.timedelta', return_value=1)
    @patch('nssutils.lib.multitasking.timestamp.get_current_time', side_effect=[0, 0, 2])
    @patch('nssutils.lib.multitasking.UtilitiesThread.terminate')
    @patch('nssutils.lib.multitasking.join_tasks')
    def test_wait_for_tasks_to_finish(self, mock_join_tasks, *_):
        task, task1 = Mock(), Mock()
        task.terminate.side_effect = None
        task1.terminate.side_effect = Exception("Error")
        mock_join_tasks.return_value = [task, task1]
        multitasking.wait_for_tasks_to_finish(tasks_list=[Mock()])


if __name__ == "__main__":
    unittest2.main(verbosity=2)
