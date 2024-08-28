#!/usr/bin/env python
import unittest2
from mock import Mock, patch
from parameterizedtestcase import ParameterizedTestCase

from nssutils.lib import model_info, persistence
from nssutils.lib.exceptions import ValidationError
from nssutils.tests import unit_test_utils


class ModelInfoUnitTests(ParameterizedTestCase):

    def setUp(self):
        unit_test_utils.setup()
        self.erbs_node = model_info.NetworkElementModel("ERBS", "15B", "-", "-", "ERBS_NODE_MODEL", "7.1.123", "1147-458-334")
        self.sgsn_node = model_info.NetworkElementModel("SGSN-MME", "15A-CP01", "CXS101289/14", "R2D15", "Sgsn", "1.3.0", "6530-077-820")
        self.mgw_node = model_info.NetworkElementModel("MGW", "15B", "-", "-", "MGW_NODE_MODEL", "3.1.123", "1484-383-806")

    def tearDown(self):
        unit_test_utils.tear_down()

    def test_validate_models_does_not_raise_a_validation_error_if_all_nes_are_supported(self):
        try:
            model_info.validate_models(["erbs", "rnc"])
        except:
            self.fail("Raised error from validate models method")

    def test_validate_models_raises_a_validation_error_if_not_all_nes_are_supported(self):
        self.assertRaises(ValidationError, model_info.validate_models, ["erbsa", "rnc"])

    @patch("nssutils.lib.model_info._get_model_info_from_cli_app")
    def test_get_supported_model_info_returns_the_expected_model_info_dict(self, get_model_info_from_cli_app):
        get_model_info_from_cli_app.side_effect = [[self.sgsn_node], [self.erbs_node]]
        expected_return_value = [self.erbs_node.ne_type, self.sgsn_node.ne_type]
        actual_return_value = model_info.get_supported_model_info(["erbs", "sgsn-mme"])
        for model in actual_return_value.itervalues():
            self.assertTrue(model[0].ne_type in expected_return_value)

    @patch("nssutils.lib.model_info._get_model_info_from_cli_app")
    def test_get_supported_model_info_mgw(self, get_model_info_from_cli_app):
        get_model_info_from_cli_app.return_value = [self.mgw_node]
        expected_return_value = {"MGW": [self.mgw_node]}
        actual_return_value = model_info.get_supported_model_info(["MGW"])
        self.assertDictEqual(actual_return_value, expected_return_value)

    @patch("nssutils.lib.enm_user_2.get_or_create_admin_user")
    def test_get_model_info_from_cli_app_correctly_parses_information_from_cli_app(self, mock_get_or_create_admin_user):
        cmd_response = [u'Ne Type\tNe Release\tProduct Identity\tRevision (R-State)\tFunctional MIM Name\tFunctional MIM Version\tModel ID',
                        u'ERBS\t-\t-\t-\tERBS_NODE_MODEL\tE.1.63\t6824-690-779',
                        u'ERBS\t-\t-\t-\tERBS_NODE_MODEL\tG.1.101\t2042-630-876']

        mock1 = Mock()
        mock2 = Mock()
        mock_get_or_create_admin_user.return_value = mock1
        mock1.enm_execute.return_value = mock2
        mock2.get_output.return_value = cmd_response

        node1, node2 = model_info._get_model_info_from_cli_app("ERBS")
        self.assertEqual([node1.mim_version, node2.mim_version], ["E.1.63", "G.1.101"])
        self.assertEqual([node1.model_id, node2.model_id], ["6824-690-779", "2042-630-876"])
        self.assertTrue(persistence.has_key("ERBS_supported_ne_models"))

    @patch("nssutils.lib.enm_user_2.get_or_create_admin_user")
    def test_get_model_info_from_cli_app_correctly_parses_mgw_info(self, mock_get_or_create_admin_user):
        cmd_response = [u'Ne Type\tNe Release\tProduct Identity\tRevision (R-State)\tFunctional MIM Name\tFunctional MIM Version\tModel ID',
                        u'MGW\t-\t-\t-\tMGW_NODE_MODEL\tC.1.193\t1484-383-806']

        mock1 = Mock()
        mock2 = Mock()
        mock_get_or_create_admin_user.return_value = mock1
        mock1.enm_execute.return_value = mock2
        mock2.get_output.return_value = cmd_response

        node1 = model_info._get_model_info_from_cli_app("MGW")[0]
        self.assertEqual(node1.mim_version, "C.1.193")
        self.assertEqual(node1.model_id, "1484-383-806")
        self.assertTrue(persistence.has_key("MGW_supported_ne_models"))

    def test_get_model_info_from_cli_app_gets_values_from_persistence_if_they_are_already_there(self):
        persistence.set("ERBS_supported_ne_models", [self.erbs_node], 20)
        node, = model_info._get_model_info_from_cli_app("ERBS")
        self.assertEqual(node.mim_version, "G.1.123")
        self.assertEqual(node.model_id, "1147-458-334")

    def test_NetworkElementModel_constructor_correctly_assigns_mim_version_appropriate_letter(self):
        self.assertEqual(self.erbs_node.mim_version, "G.1.123")


if __name__ == "__main__":
    unittest2.main(verbosity=2)
