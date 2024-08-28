#!/usr/bin/env python
import os
import time

import unittest2

import nssutils
from nssutils.lib import persistence
from nssutils.tests import func_test_utils, test_fixture, test_utils
from nssutils.tests.func_test_utils import func_dec

NSSUTILS_PATH = os.path.dirname(nssutils.__file__)
_STORAGE_PATH = os.path.join(NSSUTILS_PATH, '.persistence', 'persistence.db')


class PersistenceAcceptanceTests(unittest2.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fixture = test_fixture.AcceptanceTestFixture(cls)

    @classmethod
    def tearDownClass(cls):
        func_test_utils.module_tear_down(cls)

    def setUp(self):
        func_test_utils.setup(self)
        self.key = test_utils.get_random_string(7)
        self.value = test_utils.get_random_string(7)
        self.permanent_key = "{0}{1}".format("permanent-", test_utils.get_random_string(5))

    def tearDown(self):
        func_test_utils.tear_down(self)
        persistence.clear_all()

    @func_dec("Persistence Library", "Persistence DB can be cleared after backing DB file is deleted")
    def test_clear_function_with_no_persistence_file_runs_without_error(self):
        cmd = "rm -f {0}".format(_STORAGE_PATH)
        msg = "Removing persistence DB file before invoking persistence.clear()"
        func_test_utils.assert_command_produces_expected_rc(self, cmd, 0, msg)

        try:
            persistence.clear()
        except RuntimeError:
            self.fail(("Invoking persistence.clear() after removing persistence "
                       "DB file raised an unexpected RuntimeError"))

    @func_dec("Persistence Tool", "Key not found in persistence store after expiration")
    def test_key_no_longer_in_store_after_expiration(self):
        persistence.set(self.key, self.value, 1)
        time.sleep(1.2)
        self.assertFalse(self.key in persistence.get_all_keys())

    @func_dec("Persistence Tool", "Key not found in persistence store after deletion")
    def test_key_not_in_store_after_deletion(self):
        persistence.set(self.key, self.value, 10)
        persistence.remove(self.key)
        self.assertFalse(self.key in persistence.get_all_keys())

    @func_dec("Persistence Tool", "Key value updated correctly after set")
    def test_key_value_updated_correctly_after_set(self):
        persistence.set(self.key, self.value, 10)
        self.assertEqual(self.value, persistence.get(self.key))
        value = test_utils.get_random_string(10)
        persistence.set(self.key, value, 10)
        self.assertEqual(value, persistence.get(self.key))

    @func_dec("Persistence Tool", "TTL can be updated to prolong life of key in store")
    def test_ttl_can_be_extended_for_key(self):
        persistence.set(self.key, self.value, 10)
        time.sleep(1)
        self.assertTrue(persistence.get_ttl(self.key) < 10)
        persistence.update_ttl(self.key, 20)
        self.assertTrue(persistence.get_ttl(self.key) > 10)

    @func_dec("Persistence Tool", "Clear does not remove permanent keys from DB")
    def test_clear_does_not_remove_permanent_keys(self):
        persistence.set(self.permanent_key, self.value, -1)
        self.assertTrue(self.permanent_key in persistence.get_all_keys())
        persistence.clear()
        self.assertTrue(self.permanent_key in persistence.get_all_keys())

    @func_dec("Persistence Tool", "Clear all removes permanent keys from store")
    def test_clear_all_removes_permanent_keys(self):
        persistence.set(self.permanent_key, self.value, -1)
        self.assertTrue(self.permanent_key in persistence.get_all_keys())
        persistence.clear_all()
        self.assertFalse(self.permanent_key in persistence.get_all_keys())


if __name__ == "__main__":
    unittest2.main(verbosity=2)
