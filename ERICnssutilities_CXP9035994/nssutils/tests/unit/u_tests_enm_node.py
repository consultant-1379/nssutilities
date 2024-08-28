#!/usr/bin/env python
import unittest2
from mock import Mock, patch
from parameterizedtestcase import ParameterizedTestCase

from nssutils.lib import config
from nssutils.lib.enm_node import (APGNode, BSCNode, BaseNode, DSCNode, EPGNode, ERBSNode, MGWNode, MiniLink6352Node,
                                   MiniLinkIndoorNode, PICONode, RBSNode, RadioNode, Router6672Node, SAPCNode, SGSNNode,
                                   SSH, SnmpAuthenticationMethod, SnmpEncryptionMethod, SnmpVersion, StnNode,
                                   Subnetwork, TCU02Node, TLS, VEPGNode, VWMGNode, WMGNode,
                                   get_nodes_by_cell_size, verify_poids_on_nodes, JuniperNode, CiscoNode)
from nssutils.lib.enm_user_2 import User
from nssutils.lib.exceptions import ScriptEngineResponseValidationError
from nssutils.tests import unit_test_utils

URL = 'http://locahost'


class EnmNodeUnitTests(ParameterizedTestCase):

    @patch('time.sleep', return_value=0)
    @patch('nssutils.lib.cache.get_apache_url')
    def setUp(self, *_):  # pylint: disable=arguments-differ
        unit_test_utils.setup()
        admin_user = unit_test_utils.mock_admin_session()

        self.erbs_node = ERBSNode(
            "netsim_LTE04ERBS00003", "255.255.255.255", "5.1.120", "1094-174-285", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=ERBS-SUBNW-1', netsim="netsimlin704", simulation="LTE01", user=admin_user, oss_prefix='SubNetwork=ERBS-SUBNW-1,MeContext=netsim_LTE04ERBS00003', snmp_auth_password="", snmp_priv_password="")
        self.mgw_node = MGWNode(
            "M-MGwC1193V6lim01", "255.255.255.255", "C.1.193", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-2K-M-MGw-C1193-V6limx19", user=admin_user)
        self.sgsn_node = SGSNNode(
            "SGSN", "255.255.255.255", "C.1.193", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-SGSN", user=admin_user, primary_type="SGSN", netconf_port="22", snmp_port="25161", snmp_version=SnmpVersion.SNMP_V2C)
        self.spitfire_node = Router6672Node(
            "SPFRER60001", "255.255.255.255", "5.1.120", "1094-174-285", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-ST-SpitFire", user=admin_user)
        self.minilink_node = Router6672Node(
            "MLTN-5-4-1301", "255.255.255.255", "5.1.120", "1094-174-285", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-ST-MLTN", user=admin_user)
        self.radio_node = RadioNode(
            "RadioNode", "255.255.255.255", "C.1.193", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-RADIO", user=admin_user, primary_type="RadioNode", netconf_port="6513", snmp_port="1161", snmp_version=SnmpVersion.SNMP_V3)
        self.pico_node = PICONode(
            "PicoNode", "255.255.255.255", "C.1.193", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-RADIO", user=admin_user, primary_type="MSRBS_V1", netconf_port="6513", snmp_port="1161", snmp_version=SnmpVersion.SNMP_V3)
        self.epg_node = EPGNode(
            "EPGNode", "255.255.255.255", "C.1.193", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-RADIO", user=admin_user, primary_type="EPG", netconf_port="830", snmp_port="1161", snmp_version=SnmpVersion.SNMP_V3)

        self.vepg_node = VEPGNode(
            "EPGNode", "255.255.255.255", "C.1.193", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-RADIO", user=admin_user, primary_type="EPG", netconf_port="830", snmp_port="1161", snmp_version=SnmpVersion.SNMP_V3)

        self.wmg_node = WMGNode(
            "WMGNode", "255.255.255.255", "C.1.193", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-RADIO", user=admin_user, primary_type="EPDG", netconf_port="830", snmp_port="161", snmp_version=SnmpVersion.SNMP_V2C)

        self.vwmg_node = VWMGNode(
            "WMGNode", "255.255.255.255", "C.1.193", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-RADIO", user=admin_user, primary_type="EPDG", netconf_port="830", snmp_port="161", snmp_version=SnmpVersion.SNMP_V2C)

        self.sapc_node = SAPCNode(
            "EPGNode", "255.255.255.255", "C.1.193", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-RADIO", user=admin_user, primary_type="EPG", netconf_port="830", snmp_port="1161", snmp_version=SnmpVersion.SNMP_V3)

        self.dsc_node = DSCNode(
            "DSCNode", "255.255.255.255", "17A-R1A", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW', netsim="netsimlin704", simulation="CORE-RADIO", user=admin_user, primary_type="DSC", netconf_port="830", snmp_port="161", snmp_version=SnmpVersion.SNMP_V2C)

        self.siu02_node = StnNode(
            "SIU02Node", "255.255.255.255", "17A-R1A", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW',
            netsim="netsimlin704", simulation="CORE-SIU02", user=admin_user, primary_type="SIU02", netconf_port="830",
            snmp_port="161", snmp_version=SnmpVersion.SNMP_V2C, time_zone="GB-Eire")

        self.tcu02_node = TCU02Node(
            "TCU02Node", "255.255.255.255", "17A-R1A", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW',
            netsim="netsimlin704", simulation="CORE-TCU02", user=admin_user, primary_type="TCU02", netconf_port="830",
            snmp_port="161", snmp_version=SnmpVersion.SNMP_V2C)

        self.rbs_node = RBSNode(
            "RBSNode", "255.255.255.255", "17A-R1A", "1484-383-806", security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='SubNetwork=NETSimW',
            netsim="netsimlin704", simulation="CORE-RBS", user=admin_user, primary_type="RBS", netconf_port="830",
            snmp_port="161", snmp_version=SnmpVersion.SNMP_V2C, controlling_rnc="netsimlin704_RNC01")

        self.user = unit_test_utils.mock_enm_user()

        self.erbs_node.user = self.user
        self.mgw_node.user = self.user
        self.epg_node.user = self.user
        self.siu02_node.user = self.user
        self.tcu02_node.user = self.user
        self.rbs_node.user = self.user

        self.subnetwork = Subnetwork("Subnetwork=NETSimW", user=admin_user)
        self.zero_instance = Mock()
        self.zero_instance.get_output.return_value = [u'0 instance(s) updated']
        self.one_instance = Mock()
        self.one_instance.get_output.return_value = [u'1 instance(s) updated']
        self.credentials = Mock()
        self.credentials.get_output.return_value = [u'All credentials were created successfully']

        self.gen_counter = Mock()
        self.gen_counter.get_output.return_value = [u'FDN : NetworkElement=netsim_LTE04ERBS00003\\ngenerationCounter : 5']
        self.fm_success = Mock()
        self.fm_success.get_output.return_value = [u'FDN : NetworkElement=netsim_LTE04ERBS00003\\ncurrentServiceState : IN_SERVICE']
        self.cm_success = Mock()
        self.cm_success.get_output.return_value = [u'FDN : NetworkElement=netsim_LTE04ERBS00003\\nsyncStatus : SYNCHRONIZED']
        self.pm_success = Mock()
        self.pm_success.get_output.return_value = [u'FDN : NetworkElement=netsim_LTE04ERBS00003\\npmEnabled : true']

        self.cm_failure = Mock()
        self.cm_failure.get_output.return_value = [u'FDN : NetworkElement=netsim_LTE04ERBS00003\\nsyncStatus : UNSYNCHRONIZED']

    def tearDown(self):
        unit_test_utils.tear_down()

    def _get_node_by_type(self, node_type):
        node = None
        if node_type == "SGSN-MME":
            node = self.sgsn_node
        elif node_type == "RadioNode":
            node = self.radio_node
        elif node_type == "SAPC":
            node = self.sapc_node
        elif node_type == "EPG":
            node = self.epg_node
        elif node_type == "VEPG":
            node = self.vepg_node
        elif node_type == "WMG":
            node = self.wmg_node
        elif node_type == "vWMG":
            node = self.vwmg_node
        elif node_type == "DSC":
            node = self.dsc_node
        elif node_type == "SIU02":
            return self.siu02_node
        elif node_type == "RBS":
            return self.rbs_node

        return node

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_erbs_create(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.erbs_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_mgw_create(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.mgw_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_rbs_create(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.rbs_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_rbs_create_failed_rnc_controller_raises_error(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.zero_instance]
        self.assertRaises(ScriptEngineResponseValidationError, self.rbs_node.create)

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_epg_create(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.epg_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_wmg_create(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.wmg_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_dsc_create(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.dsc_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_spitfire_create(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.spitfire_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_minilink_create(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.minilink_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_siu02_create_mexcontext(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.siu02_node.create_mecontext()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_siu02_create(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.siu02_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_tcu02_create(self, mock_execute):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        self.tcu02_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_erbs_node_delete(self, mock_execute):
        response = Mock()
        response.get_output.return_value = [u'1 instance(s) deleted']
        mock_execute.return_value = response
        self.erbs_node.delete()

    @patch('nssutils.lib.enm_node.PmManagement.get_status')
    @patch('nssutils.lib.enm_node.FmManagement.get_status')
    @patch('nssutils.lib.enm_node.CmManagement.get_status')
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_erbs_node_manage(self, mock_execute, mock_get_cm_status, mock_get_fm_status, mock_get_pm_status):
        mock_get_cm_status.return_value = {"netsim_LTE04ERBS00003": "SYNCHRONIZED"}
        mock_get_fm_status.return_value = {"netsim_LTE04ERBS00003": "IN_SERVICE"}
        mock_get_pm_status.return_value = {"netsim_LTE04ERBS00003": "true"}
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.one_instance, self.cm_success,
                                    self.fm_success, self.pm_success, self.gen_counter]
        self.erbs_node.manage()

    @patch('nssutils.lib.enm_node.CmManagement.get_status')
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_erbs_node_unmanage(self, mock_execute, mock_get_status):
        mock_execute.side_effect = [self.one_instance, self.one_instance, self.one_instance, self.one_instance,
                                    self.cm_failure]
        mock_get_status.return_value = {"netsim_LTE04ERBS00003": "UNSYNCHRONIZED"}
        self.erbs_node.unmanage()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_erbs_node_sync(self, mock_execute):
        mock_execute.return_value = self.one_instance
        self.erbs_node.sync()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_erbs_create_fails_on_mecontext(self, mock_execute):
        mock_execute.return_value = self.zero_instance
        with self.assertRaises(ScriptEngineResponseValidationError):
            self.erbs_node.create()

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_erbs_delete_fails(self, mock_execute):
        mock_execute.return_value = self.zero_instance
        with self.assertRaises(ScriptEngineResponseValidationError):
            self.erbs_node.delete()

    def test_create_network_element_cmd_erbs(self):
        self.erbs_node.create_networkelement_cmd()
        self.assertFalse("ossModelIdentity" in self.erbs_node.CREATE_NETWORK_ELEMENT_CMD)

    def test_create_network_element_cmd_sgsn(self):
        self.sgsn_node.create_networkelement_cmd()
        self.assertFalse("ossModelIdentity" in self.erbs_node.CREATE_NETWORK_ELEMENT_CMD)

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_get_node_by_cell_size(self, mock_execute):
        response = Mock()
        response.get_output.return_value = ['SubNetwork,MeContext,ManagedElement,ENodeBFunction,'
                                            'EUtranCellFDDNodeIdParentIdEUtranCellFDDId'
                                            ' netsim_LTE 02 ERBS00003 LTE 02 ERBS00003-1'
                                            ' netsim_LTE 02 ERBS00003 LTE 02 ERBS00003-2'
                                            ' netsim_LTE 02 ERBS00003 LTE 02 ERBS00003-3'
                                            ' netsim_LTE 02 ERBS00011 LTE 02 ERBS00011-1'
                                            ' netsim_LTE 02 ERBS00011 LTE 02 ERBS00011-2'
                                            ' netsim_LTE 02 ERBS00011 LTE 02 ERBS00011-3'
                                            ' netsim_LTE 02 ERBS00012 LTE 02 ERBS00012-1'
                                            ' 3 instance(s)']
        mock_execute.return_value = response
        self.assertTrue(len(get_nodes_by_cell_size(3, self.user)) == 2)

    def test_pico_node_with_multiple_netconf_ports(self):
        self.pico_node.create_connectivity_cmd()
        self.assertEqual(self.pico_node.netconf_port, "6513")

    @ParameterizedTestCase.parameterize(
        ("node_type", "expected_protocol"),
        [
            ("SGSN-MME", SSH),
            ("RadioNode", TLS),
            ("SAPC", SSH),
            ("EPG", SSH),
            ("VEPG", SSH),
            ("WMG", SSH),
            ("vWMG", SSH),
            ("DSC", SSH),
        ]
    )
    def test_create_connectivity_cms_sets_node_type_with_correct_protocol(self, node_type, expected_protocol):
        node = self._get_node_by_type(node_type)

        node.create_connectivity_cmd()
        self.assertEqual(node.transport_protocol, expected_protocol)

    def test_set_prop_use_ssh_radionode(self):
        config.set_prop("use_ssh", True)
        self.radio_node.__init__()
        self.assertEqual(self.radio_node.transport_protocol, SSH)

    def test_create_connectivity_radionode_correct_snmp(self):
        config.set_prop('use_snmp_v3', True)
        self.radio_node.create_connectivity_cmd()
        self.assertEqual(self.radio_node.snmp_version, SnmpVersion.SNMP_V3)

    def test_create_connectivity_sgsn_correct_snmp(self):
        self.sgsn_node.create_connectivity_cmd()
        self.assertEqual(self.sgsn_node.snmp_version, SnmpVersion.SNMP_V2C)

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    @ParameterizedTestCase.parameterize(
        ("response", "expected"),
        [
            ([u'FDN : SubNetwork=ERBS-SUBNW-1\\n\\nSubNetwork=ERBS-SUBNW-2\\n\\nFDN : SubNetwork=ONRM_ROOTMO,SubNetwork=ERBS-SUBNW-2\\n\\n\\n67 instance(s)\\n","v": "2'], False),
            ([u'FDN : SubNetwork=ERBS-SUBNW-1\\n\\nSubNetwork=ERBS-SUBNW-2\\n\\nFDN : SubNetwork=ONRM_ROOTMO,SubNetwork=ERBS-SUBNW-2\\n\\n\\n760 instance(s)\\n","v": "2'], False),
            ([u'FDN : SubNetwork=ERBS-SUBNW-1\\n\\nSubNetwork=ERBS-SUBNW-2\\n\\n\\n\\n1 instance(s)\\n","v": "2'], False),
            ([u'FDN : SubNetwork=ERBS-SUBNW-1\\n\\n 0 instance(s)\\n","v": "2'], True),
            ([u'FDN : SubNetwork=ERBS-SUBNW-1\\n\\n1000 instance(s)\\n","v": "2'], False)
        ]
    )
    def test_has_no_child_mos_success(self, response, expected, mock_execute):
        mock_response = Mock()
        mock_response.get_output.return_value = response
        mock_execute.return_value = mock_response
        self.assertEqual(self.subnetwork.has_no_child_mos(), expected)

    def test_verify_poids_on_nodes_returns_all_nodes_with_no_poid(self):
        # no poid on default nodes is set
        nodes = unit_test_utils.setup_test_node_objects(2, primary_type="ERBS")

        nodes_with_poids, nodes_without_poid = verify_poids_on_nodes(nodes)
        self.assertTrue(all([
            len(nodes_with_poids) == 0,
            len(nodes_without_poid) == len(nodes)
        ]))

    def test_verify_poids_on_nodes_returns_correct_nodes_with_poid(self):
        # no poid on default nodes is set
        nodes = unit_test_utils.setup_test_node_objects(2, primary_type="ERBS")
        selected_node = nodes[0]
        poid = '123456789'
        selected_node.poid = poid

        nodes_with_poids, nodes_without_poid = verify_poids_on_nodes(nodes)
        self.assertTrue(all([
            len(nodes_with_poids) == 1,
            selected_node in nodes_with_poids,
            selected_node not in nodes_without_poid,
            len(nodes_without_poid) == 1
        ]))

    def test_to_dict(self):
        actual = self.erbs_node.to_dict()
        expected = {
            'snmp_version': self.erbs_node.snmp_version,
            'model_identity': self.erbs_node.model_identity,
            'snmp_community': self.erbs_node.snmp_community,
            'primary_type': self.erbs_node.primary_type,
            'normal_user': self.erbs_node.normal_user,
            'node_ip': self.erbs_node.node_ip,
            'snmp_port': self.erbs_node.snmp_port,
            'secure_user': self.erbs_node.secure_user,
            'mim_version': self.erbs_node.mim_version,
            'node_id': self.erbs_node.node_id,
            'node_version': self.erbs_node.node_version,
            'snmp_encryption_method': self.erbs_node.snmp_encryption_method,
            'snmp_authentication_method': self.erbs_node.snmp_authentication_method,
            'normal_password': self.erbs_node.normal_password,
            'security_state': self.erbs_node.security_state,
            'snmp_security_name': self.erbs_node.snmp_security_name,
            'secure_password': self.erbs_node.secure_password,
            'subnetwork': self.erbs_node.subnetwork,
            'revision': self.erbs_node.revision,
            'oss_prefix': self.erbs_node.oss_prefix,
            'identity': None,
            'time_zone': "",
            "tls_mode": self.erbs_node.tls_mode,
            'netconf_port': "",
            'transport_protocol': None,
            'controlling_rnc': None,
            'snmp_auth_password': "",
            'snmp_priv_password': ""
        }
        self.assertDictEqual(expected, actual)

    def test_from_dict(self):
        node_attributes = {
            "ossModelIdentity": "1094-174-285",
            "release": "5.1.120",
            "primary_type": "ERBS",
            "node_id": "LTE04ERBS00003",
            "node_ip": "255.255.255.255",
            "mim_version": "5.1.120",
            "model_identity": "1094-174-285",
            "security_state": 'ON',
            "normal_user": 'test',
            "normal_password": 'test0',
            "secure_user": 'test',
            "secure_password": 'test',
            "platform_type": "CPP",
            "subnetwork": 'SubNetwork=ERBS-SUBNW-1',
            "oss_prefix": 'SubNetwork=ERBS-SUBNW-1,MeContext=netsim_LTE04ERBS00003',
            "node_version": None,
            "snmpAgentPort": "",
            "snmp_version": None,
            "snmp_community": "",
            "snmp_security_name": "",
            "SecurityFunction": None,
            "snmp_encryption_method": None,
            "snmp_port": "",
            'netsim': 'netsimlin704',
            "snmp_authentication_method": "",
            "snmp_auth_password": "",
            "snmp_priv_password": "",
            "time_zone": "Europe/Dublin",
            "tls_mode": None,
            "netconf_port": "80",
            "transport_protocol": None,
            "controlling_rnc": None
        }

        actual = BaseNode.from_dict(node_attributes)
        self.assertEqual(
            (actual.node_name, actual.node_ip, actual.model_identity, actual.mim_version, actual.security_state,
             actual.normal_user, actual.subnetwork, actual.normal_password, actual.secure_user, actual.secure_password,
             actual.node_version, actual.oss_prefix),
            (node_attributes["node_id"], node_attributes["node_ip"], node_attributes["model_identity"], node_attributes["mim_version"],
             node_attributes["security_state"], node_attributes["normal_user"], node_attributes["subnetwork"], node_attributes["normal_password"],
             node_attributes["secure_user"], node_attributes["secure_password"], node_attributes["node_version"], node_attributes["oss_prefix"])
        )

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_connectivity_apg_node_ap_node_address_is_not_none(self, mock_enm_execute):
        user = User(username="enm_node")
        node = APGNode(node_id="MSC01", node_ip="1.2.3.4", primary_type="ECM", user=user)
        response = Mock()
        response.get_output.return_value = [u'1 instance(s)']
        mock_enm_execute.side_effect = [response]
        expected = ('cmedit create NetworkElement=MSC01,MscConnectivityInformation=1 MscConnectivityInformationId="1",'
                    'ipAddress="1.2.3.4",apnodeAIpAddress=0.0.0.0,apnodeBIpAddress=0.0.0.0 -namespace=MSC_MED '
                    '-version=1.0.0')
        node.create_connectivity()
        self.assertEqual(expected, node.CREATE_CONNECTIVITY_INFO_CMD.format(**node.create_connectivity_info_kwargs))

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_connectivity_ml6352_node_snmp_v2(self, mock_enm_execute):
        user = User(username="enm_node")
        node = MiniLink6352Node(node_id="PT202001", node_ip="1.2.3.4", primary_type="PT-2020", user=user,
                                snmp_version=SnmpVersion.SNMP_V2C)
        response = Mock()
        response.get_output.return_value = [u'1 instance(s)']
        mock_enm_execute.side_effect = [response]
        expected = ('cmedit create NetworkElement=PT202001,MINILINKOutdoorConnectivityInformation=1 '
                    'MINILINKOutdoorConnectivityInformationId=1, ipAddress="1.2.3.4", snmpVersion=SNMP_V2C,'
                    'snmpReadCommunity="public" -ns=MINI-LINK-Outdoor_MED -version=1.1.0')
        node.create_connectivity()
        self.assertEqual(expected, node.CREATE_CONNECTIVITY_INFO_CMD.format(**node.create_connectivity_info_kwargs))

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_connectivity_ml6352_node_snmp_v3(self, mock_enm_execute):
        user = User(username="enm_node")
        node = MiniLink6352Node(node_id="PT202001", node_ip="1.2.3.4", primary_type="PT-2020", user=user,
                                snmp_security_level="AUTH_PRIV", snmp_version=SnmpVersion.SNMP_V3,
                                snmp_authentication_method=SnmpAuthenticationMethod.MD5,
                                snmp_encryption_method=SnmpEncryptionMethod.CBC_DES)
        response = Mock()
        response.get_output.return_value = [u'1 instance(s)']
        mock_enm_execute.side_effect = [response]
        expected = ('cmedit create NetworkElement=PT202001,MINILINKOutdoorConnectivityInformation=1 '
                    'MINILINKOutdoorConnectivityInformationId=1, ipAddress="1.2.3.4", snmpVersion=SNMP_V3,'
                    'snmpSecurityLevel="AUTH_PRIV", snmpSecurityName="ericsson" -ns=MINI-LINK-Outdoor_MED -'
                    'version=1.1.0')
        node.create_connectivity()
        self.assertEqual(expected, node.CREATE_CONNECTIVITY_INFO_CMD.format(**node.create_connectivity_info_kwargs))

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_connectivity_mltn_node(self, mock_enm_execute):
        user = User(username="enm_node")
        node = MiniLinkIndoorNode(node_id="LH01", node_ip="1.2.3.4", primary_type="MLTN", user=user,
                                  snmp_security_level="AUTH_PRIV", snmp_version=SnmpVersion.SNMP_V3,
                                  snmp_authentication_method=SnmpAuthenticationMethod.MD5,
                                  snmp_encryption_method=SnmpEncryptionMethod.CBC_DES)
        response = Mock()
        response.get_output.return_value = [u'1 instance(s)']
        mock_enm_execute.side_effect = [response]
        expected = ('cmedit create NetworkElement=LH01,MINILINKIndoorConnectivityInformation=1 '
                    'MINILINKIndoorConnectivityInformationId=1, ipAddress="1.2.3.4", snmpSecurityLevel=AUTH_PRIV, '
                    'snmpSecurityName=ericsson -ns=MINI-LINK-Indoor_MED -version=1.0.0')
        node.create_connectivity()
        self.assertEqual(expected, node.CREATE_CONNECTIVITY_INFO_CMD.format(**node.create_connectivity_info_kwargs))

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_set_snmp_mltn_node(self, mock_enm_execute):
        user = User(username="enm_node")
        node = MiniLinkIndoorNode(node_id="LH01", node_ip="1.2.3.4", primary_type="MLTN", user=user,
                                  snmp_security_level="AUTH_PRIV", snmp_version=SnmpVersion.SNMP_V3,
                                  snmp_authentication_method=SnmpAuthenticationMethod.MD5,
                                  snmp_encryption_method=SnmpEncryptionMethod.CBC_DES)
        response = Mock()
        response.get_output.return_value = [[u'Snmp Authpriv Command OK']]
        mock_enm_execute.side_effect = [response]
        expected = ('secadm snmp authpriv --auth_algo "MD5" --auth_password "ericsson" --priv_algo "DES" '
                    '--priv_password "ericsson" -n "LH01"')
        node.set_snmp_version()
        self.assertEqual(expected, node.SET_SNMP_CMD.format(**node.set_snmp_cmd_kwargs))

    def test_set_node_security_ml6352_user_updates_v2_versus_v3(self):
        user = User(username="enm_node")
        v3_node = MiniLink6352Node(node_id="PT202001", node_ip="1.2.3.4", primary_type="PT-2020", user=user,
                                   snmp_version=SnmpVersion.SNMP_V3)
        v2_node = MiniLink6352Node(node_id="PT202001", node_ip="1.2.3.4", primary_type="PT-2020", user=user,
                                   snmp_version=SnmpVersion.SNMP_V2C)
        self.assertTrue(v2_node.set_node_security_cmd_kwargs.get("secure_user") == "admin")
        self.assertTrue(v3_node.set_node_security_cmd_kwargs.get("secure_user") == "control_user")

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_connectivity_bsc_node(self, mock_enm_execute):
        user = User(username="enm_node")
        config.set_prop('create_mecontext', True)
        node = BSCNode(node_id="BSC01", node_ip="1.2.3.4", primary_type="BSC", user=user, oss_prefix="")
        response = Mock()
        response.get_output.return_value = [u'1 instance(s)']
        mock_enm_execute.side_effect = [response]
        expected = ('cmedit create NetworkElement=BSC01,BscConnectivityInformation=1 BscConnectivityInformationId="1",'
                    'ipAddress="1.2.3.4",port="830",transportProtocol=SSH,apnodeBIpAddress="172.168.16.35",'
                    'apnodeAIpAddress="172.168.16.46" -namespace=BSC_MED -version=1.0.0')
        node.create_connectivity()
        self.assertEqual(expected, node.CREATE_CONNECTIVITY_INFO_CMD.format(**node.create_connectivity_info_kwargs))

    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_juniper_node(self, mock_enm_execute):
        user = User(username="juniper_user")
        node = JuniperNode(node_id="Juniper01", node_ip="1.2.3.4", primary_type="JUNIPER-MX", user=user)
        mock_enm_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        node.create()

    @patch('nssutils.lib.config.get_prop', return_value=True)
    @patch('nssutils.lib.config.has_prop', return_value=True)
    @patch('nssutils.lib.enm_user_2.User.enm_execute')
    def test_create_cisco_node(self, mock_enm_execute, *_):
        user = User(username="cisco_user")
        node = CiscoNode(node_id="CISCO01", node_ip="1.2.3.4", primary_type="CISCO-ASR900", user=user,
                         model_identity="a.b.c", time_zone="GB-Eire")
        mock_enm_execute.side_effect = [self.one_instance, self.one_instance, self.credentials]
        node.create()


if __name__ == "__main__":
    unittest2.main(verbosity=2)
