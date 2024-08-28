#!/usr/bin/env python
import unittest2

from nssutils.lib.enm_user_2 import User, get_or_create_admin_user
from nssutils.tests import func_test_utils, test_fixture
from nssutils.tests.func_test_utils import func_dec


class EnmUserAcceptanceTests(unittest2.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fixture = test_fixture.AcceptanceTestFixture(cls)

    @classmethod
    def tearDownClass(cls):
        func_test_utils.module_tear_down(cls)

    def setUp(self):
        func_test_utils.setup(self)
        get_or_create_admin_user()
        self.user = User('enm_utils_acceptance_tests_user1', 'TestPassw0rd', roles=['FIELD_TECHNICIAN'],
                         establish_session=True)

    def tearDown(self):
        func_test_utils.tear_down(self)

    @func_dec("Enm_User", "Create User")
    def test_010_user_create(self):
        self.user.create()

    @func_dec("Enm_User", "Enm user execute")
    def test_020_user_enm_execute(self):
        # get_output raises exception if command failed
        self.user.open_session()
        self.user.enm_execute('cmedit get * NetworkElement').get_output()
        self.user.remove_session()

    @func_dec("Enm_User", "Reestablish User session")
    def test_030_enm_execute_reestablish_session(self):
        self.user.enm_execute('cmedit get * NetworkElement').get_output()

    @func_dec("Enm_User", "Delete User")
    def test_040_user_delete(self):
        self.user.delete()


if __name__ == "__main__":
    unittest2.main(verbosity=2)
