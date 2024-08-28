#!/usr/bin/env python
import pickle
import time

import unittest2

from nssutils.lib import persistence
from nssutils.lib.persistence import persistable
from nssutils.tests import unit_test_utils


class PersistenceLibUnitTests(unittest2.TestCase):

    def setUp(self):
        self._test_key = "test_key"
        self._test_value = "test_value"

        unit_test_utils.setup()

    def tearDown(self):
        self.close_db()
        unit_test_utils.tear_down()

    def close_db(self):
        persistence.clear_all()

    def test_save_to_storage(self):
        persistence.set(self._test_key, self._test_value, 10)

        if not persistence.has_key(self._test_key):
            self.fail("Key was not found in storage after persisting")

    def test_retrieve_from_storage(self):
        persistence.set(self._test_key, self._test_value, 10)
        result = persistence.get(self._test_key)
        if result != self._test_value:
            self.fail("Key was not retrieved from storage after persisting")

    def test_key_is_expired(self):
        persistence.set(self._test_key, self._test_value, 1)
        time.sleep(1.01)
        self.assertTrue(persistence._is_expired(self._test_key))

    def test_key_is_not_expired(self):
        persistence.set(self._test_key, self._test_value, 10)
        self.assertFalse(persistence._is_expired(self._test_key))

    def test_integer_type_key_raises_value_error(self):
        self.assertRaises(ValueError, persistence.set, 123, self._test_value, 0)

    def test_nonetype_key_raises_value_error(self):
        self.assertRaises(ValueError, persistence.set, None, self._test_value, 0)

    def test_remove_key_also_removes_expiration_key(self):
        persistence.set(self._test_key, self._test_value, 10)
        persistence.remove(self._test_key)
        expiration_key = self._test_key + "-expiry"
        self.assertFalse(persistence.has_key(expiration_key))

    def test_getting_non_existant_key(self):
        self.assertEquals(None, persistence.get(self._test_key))

    def test_function_get_list_of_keys(self):
        persistence.set(self._test_key + "1", self._test_value, 2)
        persistence.set(self._test_key + "2", self._test_value, 2)
        persistence.set(self._test_key + "3", self._test_value, 2)
        key_list = set(persistence.get_all_keys())

        if len(key_list) != 3:
            self.fail("Actual length of key list returned, " + str(len(key_list)) + " did not equal expected length of 3")

    def test_setting_identical_keys_are_overwritten(self):
        persistence.set(self._test_key, self._test_value + "1", 20)
        persistence.set(self._test_key, self._test_value + "2", 30)
        persistence.set(self._test_key, self._test_value + "3", 15)
        self.assertEqual(persistence.get(self._test_key), self._test_value + "3")

    def test_clear_function_does_not_remove_infinite_keys(self):
        # Persist an infinite and a non-infinite key
        persistence.set("perm_key", "perm", -1)
        persistence.set("temp_key", "temp", 5)

        # Clear all non-infinite keys
        persistence.clear()

        # Check that the temp key was removed but the perm key was not
        self.assertTrue(len(set(persistence.get_all_keys())) == 1)

        # Remove the infinite key explicitly
        persistence.remove("perm_key")

        # Check that we have no keys now
        self.assertTrue(len(persistence.get_all_keys()) == 0)

    def test_clear_function_with_no_keys_in_persistence_runs_without_error(self):
        self.assertTrue(len(persistence.get_all_keys()) == 0)
        persistence.clear()
        self.assertTrue(len(persistence.get_all_keys()) == 0)

    def test_setting_a_nonetype_value_raises_error(self):
        self.assertRaises(ValueError, persistence.set, self._test_key, None, 0)

    def test_persistable_responds_with_new_attrs(self):
        t = Test()
        dumped = pickle.dumps(t)
        Test.__init__ = get_new_init(a=1, b=2)
        loaded = pickle.loads(dumped)
        self.assertEquals(loaded.b, 2)

    def test_persistable_replaces_class_for_persisted_object(self):
        t = Test2()
        dumped = pickle.dumps(t)
        loaded = pickle.loads(dumped)
        self.assertTrue(isinstance(loaded, Test2v2))


def get_new_init(**params):
    def init(inst, **_):
        inst.__dict__.update(**params)
    return init


@persistable
class Test(object):
    def __init__(self, a=1):
        self.a = a


class Test2v2(object):
    def __init__(self, a=1):
        self.a = a


@persistable
class Test2(object):
    REPLACE_CLASS = Test2v2

    def __init__(self, a=1):
        self.a = a


if __name__ == "__main__":
    unittest2.main(verbosity=2)
