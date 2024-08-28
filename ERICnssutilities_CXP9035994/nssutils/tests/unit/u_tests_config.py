#!/usr/bin/python
import os

import unittest2
from mock import patch

from nssutils.lib import config
from nssutils.tests import unit_test_utils


class ConfigUnitTests(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    def test_is_a_cloud_deployment_returns_true_if_emp_exists_in_the_global_config_dict(self):
        config.GLOBAL_CONFIG_DICT["EMP"] = "Exists"

        self.assertTrue(config.is_a_cloud_deployment())

    def test_is_a_cloud_deployment_returns_true_if_emp_exists_in_the_os_environment(self):
        os.environ["EMP"] = "Exists"

        self.assertTrue(config.is_a_cloud_deployment())

    def test_is_a_cloud_deployment_returns_false_if_emp_does_not_exist_in_the_os_environment_or_the_global_config_dict(
            self):
        self.assertFalse(config.is_a_cloud_deployment())

    def test_write_config_to_file(self):
        test_config_file_path = "/var/tmp/test_file"
        test_config = {"key1": "val1", "key2": "val2", "key3": "val3"}

        config._write_config_to_file(test_config, test_config_file_path)

        expected_lines = ["key1=val1\n", "key2=val2\n", "key3=val3\n"]
        with open(test_config_file_path) as config_file:
            self.assertEqual(sorted(expected_lines), sorted(config_file.readlines()))
        os.remove(test_config_file_path)

    def test_update_config_file_file_does_not_exist_throws_exception(self):
        with self.assertRaises(IOError):
            config.update_config_file("non_existant_file", "key", "value")

    @patch("nssutils.lib.filesystem.does_file_exist")
    @patch("nssutils.lib.config.parse_conf_file")
    def test_load_credentials_from_props_loads_litp_credentials(self, mock_parse_conf_file, mock_does_file_exist):
        mock_does_file_exist.return_value = True
        mock_parse_conf_file.return_value = {"username": "george", "password": "washington", "litp_username": "paul", "litp_password": "no_idea"}
        self.assertEquals(("paul", "no_idea"), config.load_credentials_from_props("litp_username", "litp_password"))


if __name__ == "__main__":
    unittest2.main(verbosity=2)
