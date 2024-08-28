#!/usr/bin/python
from datetime import datetime

import unittest2

from nssutils.lib.timestamp import is_time_diff_greater_than_time_frame
from nssutils.tests import unit_test_utils


class Timestamp(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    def test_is_time_diff_greater_than_time_frame_returns_true_if_time_diff_exceeds_time_frame(self):
        now = datetime.now()
        start_time = now.replace(hour=12, minute=50, second=1)
        end_time = now.replace(hour=12, minute=50, second=42)
        time_frame = 40
        self.assertTrue(is_time_diff_greater_than_time_frame(start_time, end_time, time_frame))

    def test_is_time_diff_greater_than_time_frame_returns_false_if_time_diff_does_not_exceeds_time_frame(self):
        now = datetime.now()
        start_time = now.replace(hour=12, minute=50, second=1)
        end_time = now.replace(hour=12, minute=50, second=41)
        time_frame = 40
        self.assertFalse(is_time_diff_greater_than_time_frame(start_time, end_time, time_frame))


if __name__ == "__main__":
    unittest2.main(verbosity=2)
