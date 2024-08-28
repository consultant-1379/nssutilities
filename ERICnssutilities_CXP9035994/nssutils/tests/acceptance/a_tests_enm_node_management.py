#!/usr/bin/env python
import unittest2

from nssutils.lib.enm_node_management import (CmManagement, FmManagement, PmManagement, ShmManagement)
from nssutils.tests import func_test_utils, test_fixture
from nssutils.tests.func_test_utils import func_dec


class ManagementAcceptanceTests(unittest2.TestCase):
    NUM_NODES = {'ERBS': 2}
    cm_management = None
    fm_management = None
    pm_management = None
    shm_management = None

    @classmethod
    def setUpClass(cls):
        cls.fixture = test_fixture.AcceptanceTestFixture(cls)
        cls.fixture.num_users = 1
        cls.fixture.user_roles = ["ADMINISTRATOR"]

    @classmethod
    def tearDownClass(cls):
        for node in cls.fixture.nodes:
            try:
                node.manage()
            except:
                pass  # We want to attempt this and not fail a test if it doesn't work out
        func_test_utils.module_tear_down(cls)

    def setUp(self):
        func_test_utils.setup(self)
        if self.fixture.nodes:
            node_ids = [node.node_id for node in self.fixture.nodes]
            if not self.cm_management:
                ManagementAcceptanceTests.cm_management = CmManagement(node_ids=node_ids, user=self.fixture.users[0])
                ManagementAcceptanceTests.fm_management = FmManagement(node_ids=node_ids, user=self.fixture.users[0])
                ManagementAcceptanceTests.pm_management = PmManagement(node_ids=node_ids, user=self.fixture.users[0])
                ManagementAcceptanceTests.shm_management = ShmManagement(node_ids=node_ids, user=self.fixture.users[0])

    def tearDown(self):
        func_test_utils.tear_down(self)

    @func_dec("CM Unsupervise", "Unsupervise Cm")
    def test_010_unsupervise_cm(self):
        ManagementAcceptanceTests.cm_management.unsupervise()

    @func_dec("CM Supervision", "Supervise Cm")
    def test_030_supervise_cm(self):
        ManagementAcceptanceTests.cm_management.supervise()

    @func_dec("Fm_Management", "Unsupervise Fm")
    def test_040_unsupervise_fm(self):
        ManagementAcceptanceTests.fm_management.unsupervise()

    @func_dec("Fm_Management", "Supervise Fm")
    def test_060_supervise_fm(self):
        ManagementAcceptanceTests.fm_management.supervise()

    @func_dec("Pm_Management", "Unsupervise Pm")
    def test_070_unsupervise_pm(self):
        ManagementAcceptanceTests.pm_management.unsupervise()

    @func_dec("Pm_Management", "Supervise Pm")
    def test_090_supervise_pm(self):
        ManagementAcceptanceTests.pm_management.supervise()

    @func_dec("Shm_Management", "Supervise Shm")
    def test_100_supervise_shm(self):
        ManagementAcceptanceTests.shm_management.supervise()

    @func_dec("Shm_Management", "Unsupervise Shm")
    def test_120_unsupervise_shm(self):
        ManagementAcceptanceTests.shm_management.unsupervise()


if __name__ == "__main__":
    unittest2.main(verbosity=2)
