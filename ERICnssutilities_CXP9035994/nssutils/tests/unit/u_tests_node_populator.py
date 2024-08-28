#!/usr/bin/env python
import os
import pkgutil

import unittest2
from mock import Mock, patch
from parameterizedtestcase import ParameterizedTestCase

from nssutils.lib import enm_node, node_populator, shell
from nssutils.lib.enm_user_2 import User
from nssutils.tests import unit_test_utils

nssutils_PATH = pkgutil.get_loader('nssutils').filename
TEST_RESOURCES_DIR = os.path.join(nssutils_PATH, 'tests', 'etc', 'network_nodes')


@patch('nssutils.lib.enm_user_2.User.open_session')
class NodePopulatorUnitTests(ParameterizedTestCase):

    def setUp(self):
        unit_test_utils.setup()
        self.user = User(username="node_pop_unit")
        self.nodes_file = os.path.join(TEST_RESOURCES_DIR, "test_nodes_data.conf")
        unit_test_utils.get_mock(self, "nssutils.lib.shell.run_cmd_on_ms", side_effect=unit_test_utils.Responder({
            ('grep dps_persistence_provider /ericsson/tor/data/global.properties',): shell.Response(rc=1, stdout="")
        }))

    def tearDown(self):
        unit_test_utils.tear_down()

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.operation_result')
    @patch('nssutils.lib.node_populator.Operation.summary')
    @patch('nssutils.lib.node_populator.Operation.print_result')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[])
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_unmanage_operation_on_one_erbs_node(self, mock_execute, *_):
        responses = []
        for resp in [[u'1 instance(s) updated'], [u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'1 instance(s) updated'], [u'syncStatus : UNSYNCHRONIZED'], [u'currentServiceState : IDLE'],
                     [u'pmEnabled : false']]:
            response = Mock()
            response.get_output.return_value = resp
            responses.append(response)
        mock_execute.side_effect = responses
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="UNMANAGE", range_start=1,
                                                 range_end=1)
        op_under_test.nodes[0].user = self.user
        op_under_test.operation()
        self.assertEqual(mock_execute.call_count, 4)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.summary')
    @patch('nssutils.lib.node_populator.thread_queue.ThreadQueue.execute')
    def test_manage_operation_on_one_erbs_node(self, mock_queue, mock_summary, *_):
        nodes = [enm_node.ERBSNode(id="ERBS05", name="ERBS05", ip="1.2.3.4", primary_type="ERBS")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="MANAGE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        op_under_test.operation()
        self.assertTrue(mock_queue.called)
        self.assertTrue(mock_summary.called)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.summary')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[])
    @patch('nssutils.lib.node_populator.thread_queue.ThreadQueue.execute')
    def test_sync_operation_on_one_erbs_node_no_subnetwork(self, mock_queue, *_):
        nodes = [enm_node.ERBSNode(id="ERBS05", name="ERBS05", ip="1.2.3.4", primary_type="ERBS")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="SYNC", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        op_under_test.operation()
        self.assertTrue(mock_queue.called)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.print_result')
    @patch('nssutils.lib.node_populator.Operation.summary')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[["Subnetwork", "Create", "PASS"]])
    @patch('nssutils.lib.node_populator.thread_queue.ThreadQueue.execute')
    def test_sync_operation_on_one_erbs_node(self, mock_queue, *_):
        nodes = [enm_node.ERBSNode(id="ERBS05", name="ERBS05", ip="1.2.3.4", primary_type="ERBS")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="SYNC", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        op_under_test.operation()
        self.assertTrue(mock_queue.called)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.print_result')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[])
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_operation_on_one_erbs_node(self, mock_execute, *_):
        responses = []
        for resp in [[u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'All credentials were created successfully']]:
            response = Mock()
            response.get_output.return_value = resp
            responses.append(response)
        mock_execute.side_effect = responses
        nodes = [enm_node.ERBSNode(id="ERBS05", name="ERBS05", ip="1.2.3.4", primary_type="ERBS")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="CREATE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        res = op_under_test.operation()
        self.assertTrue(res)
        self.assertEqual(mock_execute.call_count, 3)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.print_result')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[])
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_delete_operation_on_one_erbs_node(self, mock_execute, *_):
        responses = []
        for resp in [[u'1 instance(s) updated'], [u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'1 instance(s) updated'], [u'syncStatus : UNSYNCHRONIZED'], [u'currentServiceState : IDLE'],
                     [u'pmEnabled : false'], [u'1 instance(s)'], [u'12 instance(s) deleted']]:
            response = Mock()
            response.get_output.return_value = resp
            responses.append(response)
        mock_execute.side_effect = responses
        nodes = [enm_node.ERBSNode(id="ERBS05", name="ERBS05", ip="1.2.3.4", primary_type="ERBS")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="DELETE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        res = op_under_test.operation()
        self.assertTrue(res)
        self.assertEqual(mock_execute.call_count, 4)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.summary')
    @patch('nssutils.lib.node_populator.Operation.print_result')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[["Subnetwork", "Create", "PASS"]])
    @patch('nssutils.lib.node_populator.thread_queue.ThreadQueue.execute')
    def test_create_operation_subnetwork(self, mock_thread_queue, *_):
        nodes = [enm_node.MiniLinkIndoorNode(id="MLTN05", name="MLTN05", ip="1.2.3.4", primary_type="MLTN")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="CREATE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        op_under_test.operation()
        self.assertTrue(mock_thread_queue.called)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.summary')
    @patch('nssutils.lib.node_populator.Operation.print_result')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[["Subnetwork", "Create", "PASS"]])
    @patch('nssutils.lib.node_populator.thread_queue.ThreadQueue.execute')
    def test_delete_operation_subnetwork(self, mock_thread_queue, *_):
        nodes = [enm_node.MiniLinkIndoorNode(id="MLTN05", name="MLTN05", ip="1.2.3.4", primary_type="MLTN")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="DELETE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        op_under_test.operation()
        self.assertTrue(mock_thread_queue.called)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.print_result')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[])
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_operation_on_one_stn_node(self, mock_execute, *_):
        responses = []
        for resp in [[u'1 instance(s) updated'], [u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'All credentials were created successfully'], [u'1 instance(s) updated']]:
            response = Mock()
            response.get_output.return_value = resp
            responses.append(response)
        mock_execute.side_effect = responses
        nodes = [enm_node.StnNode(id="SIU05", name="SIU05", ip="1.2.3.4", primary_type="STN", simulation="CORE-SIU")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="CREATE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        res = op_under_test.operation()
        self.assertTrue(res)
        self.assertEqual(mock_execute.call_count, 5)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.print_result')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[])
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_operation_on_one_rnc_node(self, mock_execute, *_):
        responses = []
        for resp in [[u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'All credentials were created successfully']]:
            response = Mock()
            response.get_output.return_value = resp
            responses.append(response)
        mock_execute.side_effect = responses
        nodes = [enm_node.RNCNode(id="RNC05", name="RNC05", ip="1.2.3.4", primary_type="RNC")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="CREATE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        res = op_under_test.operation()
        self.assertTrue(res)
        self.assertEqual(mock_execute.call_count, 3)

    @patch("nssutils.lib.node_populator.shell.run_cmd_on_ms")
    def test_is_dps_provider_neo4j_returns_true_if_neo4j(self, mock_run_cmd_on_ms, *_):
        mock_run_cmd_on_ms.return_value = shell.Response(rc=0, stdout="dps_persistence_provider=neo4j")
        self.assertTrue(node_populator.is_dps_provider_neo4j())

    @patch("nssutils.lib.node_populator.shell.run_cmd_on_ms")
    def test_is_dps_provider_neo4j_returns_false_if_versant(self, mock_run_cmd_on_ms, *_):
        mock_run_cmd_on_ms.return_value = shell.Response(rc=0, stdout="dps_persistence_provider=versant")
        self.assertFalse(node_populator.is_dps_provider_neo4j())

    @patch("nssutils.lib.node_populator.shell.run_cmd_on_ms")
    def test_is_dps_provider_neo4j_returns_false_if_property_not_there(self, mock_run_cmd_on_ms, *_):
        mock_run_cmd_on_ms.return_value = shell.Response(rc=1, stdout="")
        self.assertFalse(node_populator.is_dps_provider_neo4j())

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.summary')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[])
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_populate_operation_on_one_rnc_node(self, mock_execute, *_):
        responses = []
        for resp in [[u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'All credentials were created successfully'], [u'1 instance(s) updated'],
                     [u'1 instance(s) updated'], [u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'1 instance(s) updated'], [u'1 instance(s) updated'], [u'generationCounter : 1']]:
            response = Mock()
            response.get_output.return_value = resp
            responses.append(response)
        mock_execute.side_effect = responses
        nodes = [enm_node.RNCNode(id="RNC05", name="RNC05", ip="1.2.3.4", primary_type="RNC")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="POPULATE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        res = op_under_test.operation()
        self.assertTrue(res)
        self.assertEqual(mock_execute.call_count, 6)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.print_result')
    @patch('nssutils.lib.node_populator.Operation.subnetwork')
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_populate_operation_on_one_rbs_node(self, mock_execute, mock_subnetwork, *_):
        mock_subnetwork.return_value = [[u'1 instance(s) updated', u'1 instance(s) updated', u'1 instance(s) updated']]
        responses = []
        for resp in [[u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'All credentials were created successfully'], [u'1 instance(s) updated'],
                     [u'1 instance(s) updated'], [u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'1 instance(s) updated'], [u'1 instance(s) updated'], [u'generationCounter : 1']]:
            response = Mock()
            response.get_output.return_value = resp
            responses.append(response)
        mock_execute.side_effect = responses
        nodes = [enm_node.RBSNode(id="RNC05RBS01", name="RNC05RBS01", ip="1.2.3.4", primary_type="RBS")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="POPULATE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        res = op_under_test.operation()
        self.assertTrue(res)
        self.assertEqual(mock_execute.call_count, 6)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.summary')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[])
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_operation_on_one_bsc_node(self, mock_execute, *_):
        responses = []
        for resp in [[u'1 instance(s) updated'], [u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'All credentials were created successfully']]:
            response = Mock()
            response.get_output.return_value = resp
            responses.append(response)
        mock_execute.side_effect = responses
        nodes = [enm_node.BSCNode(id="BSC05", name="BSC05", ip="1.2.3.4", primary_type="BSC")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="CREATE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        res = op_under_test.operation()
        self.assertTrue(res)
        self.assertEqual(mock_execute.call_count, 4)

    @patch('nssutils.lib.node_populator.timestamp')
    @patch('nssutils.lib.node_populator.Operation.summary')
    @patch('nssutils.lib.node_populator.Operation.subnetwork', return_value=[])
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_operation_on_one_c608_node(self, mock_execute, *_):
        responses = []
        for resp in [[u'1 instance(s) updated'], [u'1 instance(s) updated'], [u'1 instance(s) updated'],
                     [u'All credentials were created successfully'], [u'Snmp Authpriv Command OK']]:
            response = Mock()
            response.get_output.return_value = resp
            responses.append(response)
        mock_execute.side_effect = responses
        nodes = [enm_node.C608Node(id="COREC60801", name="COREC60801", ip="1.2.3.4", primary_type="RadioTNode")]
        op_under_test = node_populator.operation(input_file=self.nodes_file, operation="CREATE", nodes=nodes)
        op_under_test.nodes[0].user = self.user
        res = op_under_test.operation()
        self.assertTrue(res)
        self.assertEqual(mock_execute.call_count, 5)

    @patch('nssutils.lib.enm_node.Node.check_cm_management')
    @patch('nssutils.lib.enm_node.Node.check_pm_management')
    @patch('nssutils.lib.enm_node.Node.check_fm_management')
    @patch('nssutils.lib.enm_node.Node.enable_cm_management')
    @patch('nssutils.lib.enm_node.Node.enable_fm_management')
    @patch('nssutils.lib.enm_node.Node.enable_pm_management')
    @patch('nssutils.lib.enm_node.CppNode.check_generation_counter')
    def test_manage_add_setitem_returns_correctly_for_node_types(self, *_):
        manage = node_populator.ManageSet("SIU02")
        manage._add_set_items()
        self.assertEqual(len(manage.methods[0]), 3)
        manage = node_populator.ManageSet("ERBS")
        manage._add_set_items()
        self.assertEqual(len(manage.methods), 2)
        manage = node_populator.ManageSet("BSC")
        manage._add_set_items()
        self.assertEqual(len(manage.methods[0]), 2)
        manage = node_populator.ManageSet("vMSC")
        manage._add_set_items()
        self.assertEqual(len(manage.methods[0]), 2)


if __name__ == "__main__":
    unittest2.main(verbosity=2)
