#!/usr/bin/env python
import time

import unittest2

from nssutils.lib import config, thread_queue
from nssutils.tests import unit_test_utils


def good_func(interval):
    time.sleep(interval)


def bad_func():
    time.sleep(.001)


class ThreadQueueUnitTests(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    def _sleeper(self, interval):
        time.sleep(interval)

    def test_empty_work_item_list_produces_empty_finished_work_item_list(self):
        self.assertRaises(ValueError, thread_queue.ThreadQueue, [], 3, self._sleeper)

    def test_value_error_raised_when_non_function_given_for_function_reference(self):
        self.assertRaises(ValueError, thread_queue.ThreadQueue, [1, 1], 2, "string")

    def test_value_error_raised_when_given_non_int_num_workers(self):
        self.assertRaises(ValueError, thread_queue.ThreadQueue, [1, 1], "2", self._sleeper)

    def test_work_items_that_execute_successfully_as_threads_are_marked_as_finished(self):
        tq = thread_queue.ThreadQueue([.01, .02, .03], 3, func_ref=good_func)
        tq.execute()
        for work_item in tq.work_entries:
            self.assertTrue(work_item.finished)

    def test_work_items_that_dont_execute_successfully_are_still_marked_as_finished(self):
        tq = thread_queue.ThreadQueue([.01, .02, .03], 3, func_ref=bad_func)
        tq.execute()
        for work_item in tq.work_entries:
            self.assertTrue(work_item.finished)

    def test_num_workers_is_adjusted_down_when_work_queue_smaller_than_default_num_workers(self):
        tq = thread_queue.ThreadQueue([1, 2], 4, good_func)
        self.assertEquals(2, tq.num_workers)

    def test_num_workers_is_set_correctly_when_work_queue_larger_than_default_num_workers(self):
        tq = thread_queue.ThreadQueue([1, 2, 3, 4, 5], 2, good_func)
        self.assertEquals(2, tq.num_workers)

    def test_worker_argument_list_is_built_correctly(self):
        tq = thread_queue.ThreadQueue([1, 2], 2, good_func, ["b", 4.3])
        tq._populate_work_queue()
        self.assertEquals([1, "b", 4.3], tq.work_entries[0].arg_list)
        self.assertEquals([2, "b", 4.3], tq.work_entries[1].arg_list)

    def test_there_is_no_hang_if_all_worker_threads_die(self):
        tq = thread_queue.ThreadQueue([1, 2, 3, 4, 5, 6, 7], 7, bad_func)
        tq.execute()
        for work_item in tq.work_entries:
            self.assertTrue(work_item.finished)
            self.assertTrue(work_item.exception_raised)

    def test_done_queue_fills_with_all_work_items_from_work_queue(self):
        def test_func(x):
            x = x + 1

        work_items = [x for x in range(0, 1000)]

        tq = thread_queue.ThreadQueue(work_items, 10, test_func)
        tq.execute()

        self.assertEquals(0, tq.work_queue.qsize())
        self.assertEquals(len(work_items), tq.done_queue.qsize())

    def test_all_work_items_processed_when_some_threads_encounter_exceptions(self):
        def test_func(x):
            if x == 42 or x == 297:
                raise RuntimeError("YIKES!!!")

            x = x + 1

        work_items = [x for x in range(0, 300)]

        tq = thread_queue.ThreadQueue(work_items, 10, test_func)
        tq.execute()

        num_exceptions = 0
        num_finished = 0
        for work_item in tq.work_entries:
            if work_item.exception_raised:
                num_exceptions = num_exceptions + 1
            if work_item.finished:
                num_finished = num_finished + 1

        self.assertEquals(2, num_exceptions)
        self.assertEquals(300, num_finished)

    def test_wait_for_done_queue_to_fill_waits_for_a_specified_period_to_assert_if_workers_are_done(self):
        # Set default 'task_wait_timeout' to 3 hours
        config.set_prop("task_wait_timeout", 10800)

        tq = thread_queue.ThreadQueue([5, 7, 10], 3, func_ref=good_func, task_wait_timeout=1, task_join_timeout=0.1)
        tq.execute()

        self.assertTrue(float(tq.elapsed_time) < 5.0)


if __name__ == "__main__":
    unittest2.main(verbosity=2)
