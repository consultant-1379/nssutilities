#!/usr/bin/env python
import unittest2
from mock import patch
from parameterizedtestcase import ParameterizedTestCase

from nssutils.lib import validator
from nssutils.tests import unit_test_utils


class ValidatorUnitTests(ParameterizedTestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    @ParameterizedTestCase.parameterize(
        ('email_address', 'expected_result'),
        [
            ("pass@yahoo.com", True),
            ("pass@T-mobile.com", True),
            ("james@fail", False),
            ("f@f.f", False),
            ("f,j@ibm.com", False),
            ("123$@ericsson.se", False),
            ("james22@fail.org", True),
            ("kevin@bbc.co.uk", True),
            (1234, False),
            ("foobar", False),
            ("a" * 245 + "@email.com", True),
            ("a" * 246 + "@email.com", False),
            ("ab@c.ie", True)
        ]
    )
    def test_is_valid_email_address(self, email_address, expected_result):
        self.assertEqual(expected_result, validator.is_valid_email_address(email_address))

    @ParameterizedTestCase.parameterize(
        ('version_number', 'expected_result'),
        [
            ("1234", True),
            ("-1.2.3", False),
            ("1.2.3", True),
            ("100.200.300", True),
            ("1.2.-3", False),
        ]
    )
    def test_is_valid_version_number(self, version_number, expected_result):
        self.assertEqual(expected_result, validator.is_valid_version_number(version_number))

    @ParameterizedTestCase.parameterize(
        ('range_start', 'range_end', 'expected_result'),
        [
            (-3, 0, False),
            ("-3", 0, False),
            (1, 10, True),
            (5, 5, True),
            (4, 2, False),
            (-4, -2, False)
        ]
    )
    def test_is_valid_range(self, range_start, range_end, expected_result):
        self.assertEqual(expected_result, validator.is_valid_range(range_start, range_end))

    @patch("nssutils.lib.network.get_fqdn")
    @patch("nssutils.lib.exception.handle_invalid_argument")
    def test_validate_fqdn_with_valid_host_does_not_invoke_handle_invalid_exception(self, mock_handle_invalid_argument, mock_get_fqdn):
        mock_get_fqdn.return_value = "foo.bar.com"
        validator.validate_fqdn("1.2.3.4")
        self.assertFalse(mock_handle_invalid_argument.called)

    @patch("nssutils.lib.exception.handle_invalid_argument")
    def test_validate_version_number_with_invalid_version_invokes_handle_invalid_exception(self, mock_handle_invalid_argument):
        validator.validate_version_number("a.-1.z")
        self.assertTrue(mock_handle_invalid_argument.called)

    @patch("nssutils.lib.exception.handle_invalid_argument")
    def test_validate_email_address_with_invalid_email_invokes_handle_invalid_exception(self, mock_handle_invalid_argument):
        validator.validate_email_address("john@foobar")
        self.assertTrue(mock_handle_invalid_argument.called)

    @patch("nssutils.lib.exception.handle_invalid_argument")
    def test_validate_range_with_invalid_range_invokes_handle_invalid_exception(self, mock_handle_invalid_argument):
        validator.validate_range(-5, -10)
        self.assertTrue(mock_handle_invalid_argument.called)


if __name__ == "__main__":
    unittest2.main(verbosity=2)
