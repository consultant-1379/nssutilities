#!/usr/bin/env python
import string

import unittest2
from mock import patch
from parameterizedtestcase import ParameterizedTestCase

from nssutils.lib import arguments
from nssutils.tests import unit_test_utils


class ArgumentsUnitTests(ParameterizedTestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    @patch("nssutils.lib.init.exit")
    @ParameterizedTestCase.parameterize(
        ('addresses', 'expected_result'),
        [
            ("one@yahoo.com", False),
            ("one@yahoo.com,two@gmail.com", False),
            ("one@yahoo.com, two@gmail.com", False),
            ("james@fail", True),
            ("one@yahoo.com, abc@nothing,two@gmail.com", True),
            ("f@f.f", True),
            ("f,j@ibm.com", True),
            ("123$@ericsson.se", True),
            ("james22@fail.org", False),
            (1234, True),
            ("foobar", True)
        ]
    )
    def test_get_email_addresses(self, addresses, expected_result, mock_exit):
        arguments.get_email_addresses(addresses)
        self.assertEqual(expected_result, mock_exit.called)

        # If we expect init.exit() to have been invoked, assert that he was called with rc = 2.
        if expected_result:
            self.assertEqual((2,), mock_exit.call_args[0])

    @patch("nssutils.lib.init.exit")
    @ParameterizedTestCase.parameterize(
        ('numeric_range', 'expected_result'),
        [
            ("1-2", False),
            ("1", False),
            ("0-3", False),
            ("-2-5", True),
            ("-2", True),
            ("14-3", True),
            (5, True)
        ]
    )
    def test_get_numeric_range(self, numeric_range, expected_result, mock_exit):
        arguments.get_numeric_range(numeric_range)
        self.assertEqual(expected_result, mock_exit.called)

        # If we expect init.exit() to have been invoked, assert that he was called with rc = 2
        if expected_result:
            self.assertEqual((2,), mock_exit.call_args[0])

    def test_get_random_string_returns_correct_length(self):
        self.assertEqual(len(arguments.get_random_string(9)), 9)

    def test_get_random_string_excludes_correctly(self):
        exclude = string.ascii_letters
        self.assertNotIn(arguments.get_random_string(exclude=exclude), exclude)

    def test_get_random_string_returns_password_correctly(self):
        self.assertEqual(arguments.get_random_string(password=True)[-3:], ".8z")


if __name__ == "__main__":
    unittest2.main(verbosity=2)
