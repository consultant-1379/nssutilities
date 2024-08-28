#!/usr/bin/env python
import unittest2
from mock import Mock, patch
from parameterizedtestcase import ParameterizedTestCase

from nssutils.lib.enm_node import ERBSNode
from nssutils.lib.enm_node_management import CmManagement, FmManagement
from nssutils.lib.exceptions import ScriptEngineResponseValidationError
from nssutils.tests import unit_test_utils


class ManagementUnitTests(ParameterizedTestCase):
    def setUp(self):
        unit_test_utils.setup()

        self.user = unit_test_utils.mock_enm_user()

        self.erbs_node1 = ERBSNode(
            "netsim_LTE04ERBS00003", "255.255.255.255", "5.1.120", "1094-174-285", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=ERBS-SUBNW-1', netsim="netsimlin704", simulation="LTE01", user=self.user)

        self.erbs_node2 = ERBSNode(
            "netsim_LTE04ERBS00004", "255.255.255.250", "5.1.120", "1094-174-285", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=ERBS-SUBNW-1', netsim="netsimlin704", simulation="LTE02", user=self.user)

        self.nodes = [self.erbs_node1, self.erbs_node2]

    def tearDown(self):
        unit_test_utils.tear_down()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_supervise_raises_exception_when_supervisation_fails_on_one_or_more_nodes(self, mock_execute):
        cm_obj = CmManagement.get_management_obj(self.nodes, user=self.user)
        response = Mock()
        response.get_output.return_value = [u'1 instance(s) updated']
        mock_execute.return_value = response
        self.assertRaises(ScriptEngineResponseValidationError, cm_obj.supervise)

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_node_supervision_success(self, mock_execute):
        cm_obj = CmManagement.get_management_obj(self.nodes, user=self.user)
        response = Mock()
        response.get_output.return_value = [u'2 instance(s) updated']
        mock_execute.return_value = response

        try:
            cm_obj.supervise()
        except ScriptEngineResponseValidationError:
            self.fail("Shouldn't have raised an exception")

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_supervise_failure_with_unhandled_error(self, mock_execute):
        cm_obj = CmManagement.get_management_obj(self.nodes, user=self.user)
        response = Mock()
        response.get_output.return_value = [u'Unhandled system error 9999']
        mock_execute.return_value = response
        self.assertRaises(ScriptEngineResponseValidationError, cm_obj.supervise)

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_unsupervise_raises_exception_when_unsupervise_fails_on_one_or_more_nodes(self, mock_execute):
        cm_obj = CmManagement.get_management_obj(self.nodes, user=self.user)
        response = Mock()
        response.get_output.return_value = [u'1 instance(s) updated']
        mock_execute.return_value = response
        self.assertRaises(ScriptEngineResponseValidationError, cm_obj.unsupervise)

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_unsupervise_failure_with_unhandled_error(self, mock_execute):
        cm_obj = CmManagement.get_management_obj(self.nodes, user=self.user)
        response = Mock()
        response.get_output.return_value = [u'Something went wrong again']
        mock_execute.return_value = response
        self.assertRaises(ScriptEngineResponseValidationError, cm_obj.unsupervise)

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_supervise_regex_valid(self, mock_execute):
        cm_obj = CmManagement(user=self.user, regex="*LTE*")
        response = Mock()
        response.get_output.return_value = [u'2 instance(s) updated']
        mock_execute.return_value = response
        try:
            cm_obj.supervise()
        except ScriptEngineResponseValidationError:
            self.fail("Shouldn't have raised an exception")

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_supervise_regex_invalid(self, mock_execute):
        cm_obj = CmManagement(user=self.user, regex="*not_a_valid_node*")
        response = Mock()
        response.get_output.return_value = [u'0 instance(s) updated']
        mock_execute.return_value = response
        self.assertRaises(ScriptEngineResponseValidationError, cm_obj.supervise)

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_supervise_all_pass(self, mock_execute):
        cm_obj = CmManagement.get_management_obj(user=self.user)
        response = Mock()
        response.get_output.return_value = [u'1789 instance(s) updated']
        mock_execute.return_value = response
        try:
            cm_obj.supervise()
        except ScriptEngineResponseValidationError:
            self.fail("Shouldn't have raised an exception")

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_supervise_all_returns_zero(self, mock_execute):
        cm_obj = CmManagement.get_management_obj(user=self.user)
        response = Mock()
        response.get_output.return_value = [u'0 instance(s) updated']
        mock_execute.return_value = response
        self.assertRaises(ScriptEngineResponseValidationError, cm_obj.supervise)

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_synchronize_pass(self, mock_execute):
        cm_obj = CmManagement.get_management_obj(self.nodes, user=self.user)
        response = Mock()
        response.get_output.return_value = [u'2 instance(s) updated']
        mock_execute.return_value = response
        try:
            cm_obj.synchronize()
        except ScriptEngineResponseValidationError:
            self.fail("Shouldn't have raised an exception")

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_synchronize_failure(self, mock_execute):
        cm_obj = CmManagement.get_management_obj(self.nodes, user=self.user)
        response = Mock()
        response.get_output.return_value = [u'1 instance(s) updated']
        mock_execute.return_value = response
        self.assertRaises(ScriptEngineResponseValidationError, cm_obj.synchronize)

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_synchronize_pass_with_neType(self, mock_execute):
        cm_obj = CmManagement.get_management_obj(self.nodes, user=self.user)
        response = Mock()
        response.get_output.return_value = [u'2 instance(s) updated']
        mock_execute.return_value = response
        try:
            cm_obj.synchronize(netype='RadioNode')
        except ScriptEngineResponseValidationError:
            self.fail("Shouldn't have raised an exception")

    def test_synchronize_failure_if_object_not_take_neType(self):
        fm_obj = FmManagement.get_management_obj(self.nodes, user=self.user)
        self.assertRaises(AttributeError, fm_obj.synchronize, netype='RadioNode')


if __name__ == "__main__":
    unittest2.main(verbosity=2)
