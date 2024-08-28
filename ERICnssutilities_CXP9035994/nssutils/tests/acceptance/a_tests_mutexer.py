#!/usr/bin/env python
import time

import unittest2

from nssutils.lib import cache, multitasking, mutexer, persistence, thread_queue
from nssutils.tests import func_test_utils, test_fixture, test_utils
from nssutils.tests.func_test_utils import func_dec


class MutexerAcceptanceTests(unittest2.TestCase):

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
        persistence.clear_all()

    @func_dec("Mutexer", "Mutex list key doesn't exist before and after mutex context, but does during")
    def test_key_does_not_exist_before_or_after_acquiring_mutex(self):
        with mutexer.mutex("mutexer-unit-test", persisted=True):
            time.sleep(.2)
            self.assertEqual(0, persistence.default_db().connection.llen("mutex-mutexer-unit-test"))
            self.assertFalse("mutex-mutexer-unit-test" in persistence.get_all_keys())

        self.assertFalse("mutexer-unit-test" in persistence.get_all_keys())

    @func_dec("Mutexer", "Local mutex correctly restricts access to critical area")
    def test_local_mutex_restricts_access_to_critical_area(self):
        cache.set("acceptance-test-counter", 0)

        def _mutexed_function(value):
            with mutexer.mutex("local-mutex-test"):
                counter = cache.get("acceptance-test-counter")
                cache.set("acceptance-test-counter", (counter + value))

        tq = thread_queue.ThreadQueue([1 for _ in range(150)], 25, _mutexed_function)
        tq.execute()

        self.assertEqual(150, cache.get("acceptance-test-counter"))

    @func_dec("Mutexer", "Persistence-backed mutex correctly restricts access to critical area")
    def test_persistence_backed_mutex_restricts_access_to_critical_area(self):
        cache.set("acceptance-test-counter", 0)

        def _mutexed_function(value):
            with mutexer.mutex("local-mutex-test", persisted=True):
                counter = cache.get("acceptance-test-counter")
                cache.set("acceptance-test-counter", (counter + value))

        tq = thread_queue.ThreadQueue([1 for _ in range(150)], 25, _mutexed_function)
        tq.execute()

        self.assertEqual(150, cache.get("acceptance-test-counter"))

    @func_dec("Mutexer", "Persistence-backed mutexes are terminated when API exit is invoked")
    def test_persistence_backed_mutexes_are_terminated_on_exit(self):
        def _mutexed_function():
            with mutexer.mutex("cached-mutex-test-{0}".format(test_utils.get_random_string(8)), persisted=True):
                time.sleep(2)

        thread1 = multitasking.UtilitiesThread(None, _mutexed_function, None)
        thread2 = multitasking.UtilitiesThread(None, _mutexed_function, None)
        thread1.start()
        thread2.start()

        time.sleep(1)
        cached_mutex_keys = cache.get(mutexer.CACHE_KEY)
        self.assertIsNotNone(cached_mutex_keys)
        self.assertEquals(2, len(cached_mutex_keys))

        mutexer.terminate_mutexes()

        cached_mutex_keys = cache.get(mutexer.CACHE_KEY)
        self.assertIsNotNone(cached_mutex_keys)
        self.assertEquals(0, len(cached_mutex_keys))


if __name__ == "__main__":
    unittest2.main(verbosity=2)
