#!/usr/bin/env python
import unittest2

from parameterizedtestcase import ParameterizedTestCase

from nssutils.lib import model_info
from nssutils.tests.func_test_utils import func_dec
from nssutils.tests import func_test_utils, test_fixture


class ModelInfoAcceptanceTests(ParameterizedTestCase):

    @classmethod
    def setUpClass(cls):
        cls.fixture = test_fixture.AcceptanceTestFixture(cls)
        cls.fixture.num_users = 1
        cls.fixture.user_roles = ["ADMINISTRATOR"]

    @classmethod
    def tearDownClass(cls):
        func_test_utils.module_tear_down(cls)

    def setUp(self):
        func_test_utils.setup(self)

    def tearDown(self):
        func_test_utils.tear_down(self)

    @func_dec("Model Info", "Test getting model info for ERBS nodes returns the correct amount of NetworkElementModel objects")
    def test_get_supported_model_info_returns_correct_number_of_nodes_for_erbs_model(self):
        response_dict = model_info.get_supported_model_info(["ERBS"])
        response_nodes, = response_dict.values()
        get_supported_model_info_cmd = "cmedit describe --netype {model} --table"
        command = get_supported_model_info_cmd.format(model="ERBS")
        response = self.fixture.users[0].enm_execute(command)
        expected_nodes = len(response.get_output()) - 4
        self.assertEqual(len(response_nodes), expected_nodes)

    @func_dec("Model Info", "Test all RadioNodes and SGSN-MME nodes have revision versions")
    def test_get_supported_model_info_returns_all_radio_nodes_and_sgsn_mme_nodes_with_revision_numbers(self):
        response_dict = model_info.get_supported_model_info(["SGSN-MME", "RadioNode"])
        nodes1, nodes2 = response_dict.values()
        nodes = nodes1 + nodes2
        self.assertTrue(all([node.revision for node in nodes]))


if __name__ == "__main__":
    unittest2.main(verbosity=2)
