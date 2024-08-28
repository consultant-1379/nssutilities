#!/usr/bin/env python
import StringIO
import logging

import unittest2
from mock import Mock, patch

from nssutils.lib import config, log
from nssutils.tests import unit_test_utils


class LogUnitTests(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    def test_check_use_color_returns_true_if_config_get_prop_equals_true(self):
        config.set_prop("print_color", "true")
        test_check_color = log._check_use_color()
        self.assertTrue(test_check_color)

    def test_check_use_color_returns_false_if_config_get_prop_does_not_equal_true(self):
        config.set_prop("print_color", "false")
        test_check_color = log._check_use_color()
        self.assertFalse(test_check_color)

    def test_log_entry_changes_a_non_string_parameter_argument_to_a_string(self):
        a_list = ["some value"]
        try:
            log.log_entry(a_list)
        except TypeError:
            self.fail("List parameter was not converted to a string for use with the function")

    def test_simplified_log_stop(self):
        logger = logging.getLogger('test-logger')
        stream = StringIO.StringIO()
        handler = logging.StreamHandler(stream)
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.info('test')
        logging.shutdown()
        logger.info('wildlife')
        self.assertTrue('wildlife' in stream.getvalue())
        log.logger = logger
        log.shutdown_handlers()
        logger.info('notlogged')
        self.assertFalse('notlogged' in stream.getvalue())

    @patch("os.makedirs")
    @patch("os.path")
    def test_log_init_raises_error_when_no_log_dir_created(self, mock_os_path, mock_os_makedirs):
        mock_os_path.exists = Mock(return_value=False)
        mock_os_path.isdir = Mock(return_value=False)
        self.assertRaises(RuntimeError, log.log_init)

        self.assertTrue(mock_os_path.exists.assert_called)
        self.assertTrue(mock_os_makedirs.assert_called)
        self.assertEquals(mock_os_path.isdir.call_count, 2)

    @patch("os.makedirs")
    @patch("os.remove")
    @patch("os.path")
    def test_log_init_log_path_is_removed_if_is_not_directory_and_new_log_dir_created(self, mock_os_path, mock_os_remove, mock_os_makedirs):
        mock_os_path.exists = Mock(return_value=True)
        mock_os_path.isdir = Mock(side_effect=[False, False, True])

        log.log_init()

        self.assertEquals(mock_os_remove.call_count, 1)
        self.assertEquals(mock_os_makedirs.call_count, 1)
        self.assertEquals(mock_os_path.isdir.call_count, 3)

    @patch("os.makedirs")
    @patch("os.remove")
    @patch("os.path")
    def test_prepare_log_dir_creates_log_directory_when_no_path_exists(self, mock_os_path, mock_os_remove, mock_os_makedirs):
        mock_os_path.exists = Mock(return_value=False)
        mock_os_path.isdir = Mock(side_effect=[False, True])

        log.log_init()

        self.assertEquals(mock_os_makedirs.call_count, 1)
        self.assertFalse(mock_os_remove.called)
        self.assertEquals(mock_os_path.isdir.call_count, 2)


if __name__ == "__main__":
    unittest2.main(verbosity=2)
