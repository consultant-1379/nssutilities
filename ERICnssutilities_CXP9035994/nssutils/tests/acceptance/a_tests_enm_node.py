#!/usr/bin/env python
import time

import unittest2

from nssutils.lib.enm_node import NODE_CLASS_MAP, SGSNNode, SnmpVersion
from nssutils.lib.enm_user_2 import get_or_create_admin_user
from nssutils.tests import func_test_utils, test_fixture
from nssutils.tests.func_test_utils import func_dec


class EnmNodeAcceptanceTests(unittest2.TestCase):

    # NUM_NODES = {'ERBS': 1, 'MGW': 1}
    NUM_NODES = {'ERBS': 1, 'MGW': 1}

    @classmethod
    def setUpClass(cls):
        cls.fixture = test_fixture.AcceptanceTestFixture(cls)

    @classmethod
    def tearDownClass(cls):
        for node in cls.fixture.nodes:
            try:
                node.manage()
            except:
                pass  # We want to attempt this and not fail a test if it doesn't work out
        func_test_utils.module_tear_down(cls)

    def setUp(self):
        self.test_nodes = {}
        func_test_utils.setup(self)
        for node in self.fixture.nodes:
            if node.primary_type == 'SGSN':
                self.sgsn_node = SGSNNode(
                    node_id=node.node_id,
                    node_ip=node.node_ip,
                    mim_version=node.mim_version,
                    model_identity=node.model_identity,
                    security_state=node.security_state,
                    normal_user=node.normal_user,
                    normal_password=node.normal_password,
                    secure_user=node.secure_user,
                    secure_password=node.secure_password,
                    subnetwork=node.subnetwork,
                    netsim=node.netsim,
                    simulation=node.simulation,
                    revision=node.revision,
                    identity=node.identity,
                    primary_type=node.primary_type,
                    node_version=node.node_version,
                    snmp_port=node.snmp,
                    snmp_version=SnmpVersion.SNMP_V2C,
                    user=get_or_create_admin_user(),
                )
            else:
                self.test_nodes[node.primary_type] = NODE_CLASS_MAP[node.primary_type](
                    node_id=node.node_id,
                    node_ip=node.node_ip,
                    mim_version=node.mim_version,
                    model_identity=node.model_identity,
                    security_state=node.security_state,
                    normal_user=node.normal_user,
                    normal_password=node.normal_password,
                    secure_user=node.secure_user,
                    secure_password=node.secure_password,
                    subnetwork=node.subnetwork,
                    netsim=node.netsim,
                    simulation=node.simulation,
                    revision=node.revision,
                    identity=node.identity,
                    primary_type=node.primary_type,
                    node_version=node.node_version,
                    user=get_or_create_admin_user(),
                )

    def tearDown(self):
        func_test_utils.tear_down(self)

    @func_dec("ENM Node", "Unmanage an ERBS node")
    def test_010_erbs_node_unmanage(self):
        self.test_nodes["ERBS"].disable_cm_management()
        self.test_nodes["ERBS"].disable_fm_management()
        self.test_nodes["ERBS"].disable_pm_management()
        self.test_nodes["ERBS"].disable_shm_management()
        time.sleep(10)
        self.test_nodes["ERBS"].check_cm_management(status='UNSYNCHRONIZED')

    @func_dec("ENM Node", "Delete an ERBS node")
    def test_020_erbs_node_delete(self):
        self.test_nodes["ERBS"].delete()

    @func_dec("ENM Node", "Create an ERBS node")
    def test_030_erbs_node_create(self):
        self.test_nodes["ERBS"].create()

    @func_dec("ENM Node", "Unmanage an SGSN node")
    def test_040_sgsn_node_unmanage(self):
        self.sgsn_node.disable_cm_management()
        self.sgsn_node.disable_fm_management()
        self.sgsn_node.disable_pm_management()
        self.sgsn_node.disable_shm_management()
        time.sleep(10)
        self.sgsn_node.check_cm_management(status='UNSYNCHRONIZED')

    @func_dec("ENM Node", "Delete an SGSN node")
    def test_050_sgsn_node_delete(self):
        self.sgsn_node.delete()

    @func_dec("ENM Node", "Create an SGSN node")
    def test_060_sgsn_node_create(self):
        self.sgsn_node.create()


if __name__ == "__main__":
    unittest2.main(verbosity=2)
