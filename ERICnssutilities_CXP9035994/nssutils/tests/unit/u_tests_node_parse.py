#!/usr/bin/env python
import base64
import collections
import os
import pkgutil

import unittest2
from mock import Mock, mock_open, patch

from nssutils.lib import config, filesystem, node_parse
from nssutils.lib.enm_node import NODE_CLASS_MAP
from nssutils.tests import unit_test_utils

COMMON_TESTS_PATH = os.path.join(pkgutil.get_loader('nssutils').filename, 'tests')


class NodeParseUnitTests(unittest2.TestCase):
    test_nodes_xml_dir = os.path.join(COMMON_TESTS_PATH, "etc", "network_nodes")
    filtered_nodes_file = os.path.join(test_nodes_xml_dir, "filtered_nodes_file")
    comecim_nodes_file = os.path.join(test_nodes_xml_dir, "nonerbs_nodes")
    test_xml_file_with_ipv4_atttributes = os.path.join(test_nodes_xml_dir, "arne_xml_ipv4_attributes.xml")
    test_xml_file_with_ipv6_atttributes = os.path.join(test_nodes_xml_dir, "arne_xml_ipv6_attributes.xml")
    test_xml_custom_username_password = os.path.join(test_nodes_xml_dir, "arne_xml_with_custom_username_password.xml")
    test_nodes_data_file = os.path.join(test_nodes_xml_dir, "test_nodes_data.conf")
    subnetwork_file = os.path.join(test_nodes_xml_dir, "subnetwork.xml")
    no_subnetwork_file = os.path.join(test_nodes_xml_dir, "no_subnetwork.xml")
    empty_file = os.path.join(test_nodes_xml_dir, "empty.xml")
    comecim_xml_file = os.path.join(test_nodes_xml_dir, "comecim.xml")

    def setUp(self):
        unit_test_utils.setup()
        self.test_file = '/tmp/node_parse_test.txt'
        if not filesystem.does_file_exist(self.test_file):
            filesystem.touch_file(self.test_file)
        self.model_dict = {key: [] for key in NODE_CLASS_MAP.keys()}
        self.model_dict['SGSN-MME'] = self.model_dict['MINI-LINK-Indoor'] = self.model_dict['Router6672'] = []
        self.dups = Mock()
        self.dups.ips = {}
        self.dups.managed_element_ids = {}

    def tearDown(self):
        if filesystem.does_file_exist(self.test_file):
            filesystem.delete_file(self.test_file)
        unit_test_utils.tear_down()

    def test_get_xml_files_returns_empty_list(self):
        self.assertEqual([], node_parse.get_xml_files("/tests/takes/ages/"))

    def test_get_xml_files_returns_list(self):
        self.assertTrue(len(node_parse.get_xml_files(self.test_nodes_xml_dir)) > 0)

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_validate_on_unsupported_primary_types(self, *_):
        data_dict = {'primary_type': 'RXI', 'invalid_fields': '', 'node_name': '', 'node_ip': '147.123.124.23'}
        validate = node_parse.Validate(data_dict, self.dups)
        validate.validate()
        self.assertTrue('primary_type' in validate.node_data['invalid_fields'])

    def test_validate_on_empty_node_name(self):
        data_dict = {'primary_type': 'BSP', 'invalid_fields': '', 'node_name': '', 'node_ip': '147.123.124.23'}
        validate = node_parse.Validate(data_dict, self.dups)
        validate.validate()
        self.assertTrue('node_name' in validate.node_data['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_validate_on_empty_node_ip(self, *_):
        data_dict = {'primary_type': 'STP', 'invalid_fields': '', 'node_name': 'LTE01', 'node_ip': ''}
        validate = node_parse.Validate(data_dict, self.dups)
        validate.validate()
        self.assertTrue('node_ip' in validate.node_data['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_validate_on_duplicate_ip(self, *_):
        data_dict1 = collections.OrderedDict([('primary_type', 'RXI'), ('invalid_fields', ''), ('node_name', 'LTE01'), ('node_ip', '147.123.124.23')])
        data_dict2 = collections.OrderedDict([('primary_type', 'RXI'), ('invalid_fields', ''), ('node_name', 'LTE02'), ('node_ip', '147.123.124.23')])
        parsed_data = [data_dict1, data_dict2]
        node_parse.validate(parsed_data)
        self.assertTrue('node_ip' in data_dict2['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_validate_on_duplicate_ipv6(self, *_):
        data_dict1 = collections.OrderedDict([('primary_type', 'RXI'), ('invalid_fields', ''), ('node_name', 'LTE01'), ('node_ip', '2001:0db8:85a3:0000:0000:8a2e:0370:7334')])
        data_dict2 = collections.OrderedDict([('primary_type', 'RXI'), ('invalid_fields', ''), ('node_name', 'LTE02'), ('node_ip', '2001:0db8:85a3:0000:0000:8a2e:0370:7334')])
        parsed_data = [data_dict1, data_dict2]
        node_parse.validate(parsed_data)
        self.assertTrue('node_ip' in data_dict2['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_validate_on_duplicate_managed_element_id(self, *_):
        data_dict1 = collections.OrderedDict([('primary_type', 'RXI'), ('invalid_fields', ''), ('node_name', 'LTE01'), ('node_ip', '147.123.124.23')])
        data_dict2 = collections.OrderedDict([('primary_type', 'RXI'), ('invalid_fields', ''), ('node_name', 'LTE01'), ('node_ip', '147.123.124.24')])
        parsed_data = [data_dict1, data_dict2]
        node_parse.validate(parsed_data)
        self.assertTrue('node_name' in data_dict2['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_validate_on_bad_ipv4(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'RXI'), ('invalid_fields', ''), ('node_name', 'ggg'), ('node_ip', '141')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue('node_ip' in data_dict['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_validate_on_bad_ipv6(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'RXI'), ('invalid_fields', ''), ('node_name', 'ggg'), ('node_ip', '2606:ae00:ffe0:6c11::2:9:P')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue('node_ip' in data_dict['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse.CppValidate.validate")
    def test_cpp_validate_called_erbs(self, mock_cpp_validate, *_):
        mock_cpp_validate.return_value = None
        data_dict = collections.OrderedDict([('primary_type', 'ERBS'), ('invalid_fields', ''), ('node_name', 'LTE01'), ('node_ip', '147.123.124.23'), ('mim_version', ''), ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue(mock_cpp_validate.called)

    @patch('nssutils.lib.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse.CppValidate.validate")
    def test_cpp_validate_called_mgw(self, mock_cpp_validate, *_):
        mock_cpp_validate.return_value = None
        data_dict = collections.OrderedDict([('primary_type', 'MGW'), ('invalid_fields', ''), ('node_name', 'LTE01'),
                                             ('node_ip', '147.123.124.23'), ('mim_version', ''),
                                             ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue(mock_cpp_validate.called)

    @patch('nssutils.lib.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse.COMECIMValidate.validate")
    def test_comecim_validate_called_tcu02_node(self, mock_comecim_validate, *_):
        mock_comecim_validate.return_value = None
        data_dict = collections.OrderedDict(
            [('primary_type', 'TCU02'), ('invalid_fields', ''), ('node_name', 'TCU0201'), ('node_ip', '147.123.124.23'),
             ('mim_version', ''), ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue(mock_comecim_validate.called)

    @patch('nssutils.lib.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse.Validate.validate")
    def test_comecim_validate_catches_missing_node_version(self, *_):
        model = {'17A': {'oss_model_identity': '17A', 'identity': 'CXP9024055_4', 'revision': 'R1A'}}
        data_dict = {'primary_type': 'TCU02', 'invalid_fields': '', 'identity': '', 'oss_model_identity': '17A',
                     'revision': '', 'node_name': 'TCU0201', 'node_ip': '147.123.124.23'}
        node_parse.COMECIMValidate(data_dict, self.dups, model).validate()
        self.assertEqual(data_dict['invalid_fields'], "node_version: key missing from properties.conf")

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_comecim_validate_catches_missing_oss_mode_identity(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'TCU02'), ('invalid_fields', ''), ('revision', ''),
                                             ('identity', ''), ('node_name', 'TCU0201'), ('node_version', '15B'),
                                             ('node_ip', '147.123.124.23')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertEqual(data_dict['invalid_fields'], "oss_model_identity: key missing from properties.conf")

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_comecim_validate_catches_missing_revision(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'TCU02'), ('invalid_fields', ''),
                                             ('oss_model_identity', ''), ('identity', ''), ('node_name', 'TCU0201'),
                                             ('node_version', '15B'), ('node_ip', '147.123.124.23')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertEqual(data_dict['invalid_fields'], "revision: key missing from properties.conf")

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_comecim_validate_catches_missing_identity(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'TCU02'), ('invalid_fields', ''),
                                             ('oss_model_identity', ''), ('revision', ''), ('node_name', 'TCU0201'),
                                             ('node_version', '15B'), ('node_ip', '147.123.124.23')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertEqual(data_dict['invalid_fields'], "identity: key missing from properties.conf")

    @patch('nssutils.lib.node_parse.Validate.validate')
    def test_comecim_validate_catches_missing_model_info(self, *_):
        model = {'17A-R1A': {'oss_model_identity': '17A-R1A', 'identity': 'CXP9024055_4', 'revision': 'R1A'},
                 '17A': {'oss_model_identity': '17A', 'identity': 'CXP9024055_4'}}
        data_dict = {'primary_type': 'SIU02', 'invalid_fields': '', 'identity': '', 'oss_model_identity': '17A',
                     'revision': '', 'node_name': 'SIU0201', 'node_version': '17A', 'node_ip': '147.123.124.23'}
        node_parse.COMECIMValidate(data_dict, self.dups, model).validate()
        self.assertTrue("oss model identity" in data_dict['invalid_fields'])

    @patch("nssutils.lib.node_parse.Validate.validate")
    def test_comecim_validate_tcu04(self, *_):
        model = {'17A': {'oss_model_identity': '17A', 'identity': 'CXP9024055_4', 'revision': '17A'}}
        data_dict = {'primary_type': 'TCU02', 'invalid_fields': '', 'identity': '', 'oss_model_identity': '17A',
                     'revision': '', 'node_name': 'TCU0401', 'node_version': '17A', 'node_ip': '147.123.124.23'}
        node_parse.COMECIMValidate(data_dict, self.dups, model).validate()
        self.assertEqual(data_dict['invalid_fields'], '')

    @patch('nssutils.lib.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse.COMECIMValidate.validate")
    def test_comecim_validate_called_dsc_node(self, mock_comecim_validate, *_):
        mock_comecim_validate.return_value = None
        data_dict = collections.OrderedDict([('primary_type', 'DSC'), ('invalid_fields', ''), ('node_name', 'DSC01'), ('node_ip', '147.123.124.23'), ('mim_version', ''), ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue(mock_comecim_validate.called)

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_erbs_validate_on_empty_mim(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'ERBS'), ('invalid_fields', ''), ('node_name', 'LTE01'), ('node_ip', '147.123.124.23'), ('mim_version', ''), ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue('mim_version' in data_dict['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_erbs_validate_on_bad_mim_format(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'ERBS'), ('invalid_fields', ''), ('node_name', 'LTE01'), ('node_ip', '147.123.124.23'), ('mim_version', '1.badMim'), ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue('mim_version' in data_dict['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_erbs_validate_on_good_mim_format_but_no_key(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'ERBS'), ('invalid_fields', ''), ('node_name', 'LTE01'), ('node_ip', '147.123.124.23'), ('mim_version', 'D.1.560'), ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue('mim_version' in data_dict['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_erbs_validate_on_good_mim(self, mock_model_info, *_):
        response = Mock()
        response.mim_name = 'Mme'
        response.mim_version = 'E.1.63'
        response.model_id = '15B-CP11'
        response.ne_release = '15B'
        response.ne_type = 'ERBS'
        response.revision = 'R12A27'
        response.software_version = 'CXS101289/13'
        self.model_dict["ERBS"] = [response]
        mock_model_info.return_value = self.model_dict
        data_dict = collections.OrderedDict([('primary_type', 'ERBS'), ('invalid_fields', ''), ('node_name', 'LTE01'),
                                             ('node_ip', '147.123.124.23'), ('mim_version', 'E.1.63'),
                                             ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue(data_dict['oss_model_identity'] != "")

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_rbs_validate_on_empty_mim(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'RBS'), ('invalid_fields', ''), ('node_name', 'RBS01'), ('node_ip', '147.123.124.23'), ('mim_version', ''), ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue('mim_version' in data_dict['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_rbs_validate_on_bad_mim_format(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'RBS'), ('invalid_fields', ''), ('node_name', 'RBS01'), ('node_ip', '147.123.124.23'), ('mim_version', '1.badMim'), ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue('mim_version' in data_dict['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse.Validate.validate")
    def test_rbs_validate_on_good_mim_format_but_no_key(self, *_):
        model = {'17A': {'oss_model_identity': '17A', 'identity': 'CXP9024055_4', 'revision': '17A',
                         'mim_version': '1234.1234.1234'}}
        data_dict = {'primary_type': 'RBS02', 'invalid_fields': '', 'identity': '', 'oss_model_identity': '',
                     'revision': '', 'node_name': 'RBS01', 'node_version': '17A', 'node_ip': '147.123.124.23'}
        node_parse.CppValidate(data_dict, self.dups, model).validate()
        self.assertTrue('mim_version' in data_dict['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse.Validate.validate")
    def test_rbs_validate_on_invalid_mim_mapping(self, *_):
        model = {'17A': {'oss_model_identity': '17A', 'identity': 'CXP9024055_4', 'revision': '17A',
                         'mim_version': 'S2.1.100'}}
        data_dict = {'primary_type': 'RBS02', 'invalid_fields': '', 'identity': '', 'oss_model_identity': '',
                     'revision': '', 'node_name': 'RBS01', 'node_version': '17A', 'node_ip': '147.123.124.23'}
        node_parse.CppValidate(data_dict, self.dups, model).validate()
        self.assertFalse(data_dict['oss_model_identity'] != "")

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_rbs_validate_on_good_mim(self, mock_model_info, *_):
        response = Mock()
        response.mim_name = 'RBS'
        response.mim_version = 'S2.2.100'
        response.model_id = '17B-U.4.630'
        response.ne_release = '17Q.2'
        response.ne_type = 'RBS'
        response.revision = 'R12A27'
        response.software_version = 'CXS101289/13'
        self.model_dict["RBS"] = [response]
        mock_model_info.return_value = self.model_dict
        data_dict = collections.OrderedDict([('primary_type', 'RBS'), ('invalid_fields', ''), ('node_name', 'RBS01'),
                                             ('node_ip', '147.123.124.23'), ('mim_version', 'S2.2.100'), ('oss_model_identity', '')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue(data_dict['oss_model_identity'] != "")

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_comecim_validate_on_empty_node_version(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'SGSN'), ('invalid_fields', ''), ('node_name', 'LTE01'), ('node_version', ''), ('node_ip', '147.123.124.23'), ('oss_model_identity', '147.123.124.23'), ('revision', '147.123.124.23'), ('identity', '147.123.124.23')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue('node_version' in data_dict['invalid_fields'])

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_comecim_validate_no_model_information(self, *_):
        data_dict = collections.OrderedDict([('primary_type', 'SGSN'), ('invalid_fields', ''), ('node_name', 'LTE01'), ('node_version', '17B'), ('node_ip', '147.123.124.23')])
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue('oss_model_identity' in data_dict['invalid_fields'])

    @patch('nssutils.lib.node_parse.Validate.validate')
    def test_comecim_validate_could_not_retrieve_oss_model_identity(self, *_):
        model = {'17A': {'identity': 'CXP9024055_4', 'revision': '17A'}}
        data_dict = {'primary_type': 'TCU02', 'invalid_fields': '', 'identity': '', 'oss_model_identity': '17A',
                     'revision': '', 'node_name': 'TCU0401', 'node_version': '17A', 'node_ip': '147.123.124.23'}
        node_parse.COMECIMValidate(data_dict, self.dups, model).validate()
        self.assertTrue('oss_model_identity' in data_dict['invalid_fields'])

    @patch('nssutils.lib.node_parse.load_model_info')
    def test_comecim_validate_could_retrieve_oss_model_identity(self, mock_model_info, *_):
        response = Mock()
        self.model_dict["SGSN-MME"] = [response]
        mock_model_info.return_value = self.model_dict
        data_dict = {'primary_type': 'SGSN', 'invalid_fields': '', 'oss_model_identity': '', 'revision': '',
                     'identity': '', 'node_name': 'LTE01', 'node_version': '15B', 'node_ip': '147.123.124.23'}
        mock_model_info.return_value = {'15B': {'oss_model_identity': '15B-CP01', 'identity': 'CXP9022530/25',
                                                'revision': 'R5B49'}}
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue(data_dict['oss_model_identity'] != '' and data_dict['revision'] != '' and data_dict['identity'] != '')

    @patch('nssutils.lib.model_info.get_supported_model_info')
    def test_comecim_validate_on_invalid_node_version_from_xml(self, *_):
        data_dict = collections.OrderedDict(
            [('primary_type', 'SGSN'), ('invalid_fields', ''), ('oss_model_identity', ''), ('revision', ''), ('identity', ''), ('node_name', 'LTE01'), ('node_version', '16A-CP05'), ('node_ip', '147.123.124.23')])
        config.set_prop("SGSN_17B", "{'revision':'R50L01', 'identity':'CXS101289'}")
        parsed_data = [data_dict]
        node_parse.validate(parsed_data)
        self.assertTrue(data_dict['invalid_fields'] != '')

    def test_read_csv_returns_empty_list(self):
        self.assertEqual([], node_parse.read_csv(self.filtered_nodes_file, None, None))

    def test_read_csv_returns_list(self):
        self.assertTrue(len(node_parse.read_csv(self.comecim_nodes_file, 1, 2)) > 0)

    def test_read_csv_returns_text_password(self):
        nodes = node_parse.read_csv(self.comecim_nodes_file, 1, 2)
        self.assertEqual(nodes[0].secure_password, "secret")

    def test_get_node_data_returns_data(self):
        self.assertTrue(len(node_parse.get_node_data(self.comecim_nodes_file)) > 0)

    def test_get_node_data_throws_error(self):
        self.assertRaises(RuntimeError, node_parse.get_node_data, "blah")

    def test_get_node_data_skips_nodes_with_invalid_snmp_info(self):
        invalid_nodes_file = os.path.join(self.test_nodes_xml_dir, "invalid_snmp_info")
        res = node_parse.get_node_data(invalid_nodes_file)
        self.assertEqual(len(res), 0)

    def test_build_nodes_returns_empty_list(self):
        self.assertEqual([], node_parse.build_nodes([[]], 0, 0))

    @patch("nssutils.lib.exception.handle_invalid_argument")
    @patch("nssutils.lib.filesystem.does_file_exist")
    def test_update_handles_bad_file(self, mock_does_file_exist, mock_handle_invalid_argument):
        mock_does_file_exist.return_value = False
        mock_handle_invalid_argument.side_effect = SystemExit("Exit Message")
        with self.assertRaises(SystemExit):
            node_parse.update("nodes_file", treatas_file="treatas_file")
        self.assertTrue(mock_handle_invalid_argument.called)

    @patch("nssutils.lib.exception.process_exception")
    @patch("nssutils.lib.node_parse._load_model_ids")
    @patch("nssutils.lib.filesystem.does_file_exist")
    def test_update_process_exception(self, mock_does_file_exist, mock_load_model_ids, mock_process_exception):
        mock_does_file_exist.return_value = True
        mock_load_model_ids.return_value = {}
        mock_process_exception.side_effect = SystemExit("Exit Message")
        with self.assertRaises(SystemExit):
            node_parse.update("nodes_file", treatas_file="treatas_file")
        self.assertTrue(mock_process_exception.called)

    @patch("nssutils.lib.node_parse.write_csv")
    @patch("nssutils.lib.node_parse.update_nodes")
    @patch("nssutils.lib.node_parse._load_model_ids")
    @patch("nssutils.lib.filesystem.does_file_exist")
    def test_update_calls_write_csv(self, mock_does_file_exist, mock_load_model_ids, mock_update_nodes, mock_write_csv):
        mock_does_file_exist.return_value = True
        mock_load_model_ids.return_value = {"model_ids"}
        mock_update_nodes.return_value = [""]
        mock_write_csv.return_value = None
        node_parse.update("nodes_file", treatas_file="treatas_file")
        self.assertTrue(mock_write_csv.called)

    def test_load_model_ids_returns_empty_dict(self):
        treatas_file = os.path.join(self.test_nodes_xml_dir, "treatas_empty")
        treat_as = node_parse._load_model_ids(treatas_file)
        self.assertFalse(treat_as)

    def test_load_model_ids_returns_data(self):
        treatas_file = os.path.join(self.test_nodes_xml_dir, "treatas")
        treat_as = node_parse._load_model_ids(treatas_file)
        self.assertTrue(treat_as)

    def test_build_nodes_returns_nodes_list(self):
        data_list = [{'model_identity': '5783-904-386', 'primary_type': 'ERBS', 'normal_user': 'netsim', 'node_ip': '10.241.164.11', 'netsim': 'netsimlin547.athtem.eei.ericsson.se', 'secure_user': 'netsim', 'mim_version': '6.1.101', 'node_id': 'netsimlin547_LTE07ERBS00071', 'normal_password': 'netsim', 'security_state': 'ON', 'secure_password': 'netsim', 'identity': None, 'node_version': None, 'simulation': 'LTEF1101x160-RV-FDD-LTE07', 'subnetwork': 'SubNetwork=ERBS-SUBNW-1', 'revision': None, 'source_type': None}]
        self.assertTrue(len(node_parse.build_nodes(data_list, None, None)) > 0)

    def test_build_nodes_skips_invalid_node(self):
        data_list = [{'model_identity': '5783-904-386', 'primary_type': 'xxx', 'normal_user': 'netsim', 'node_ip': '10.241.164.10', 'netsim': 'netsimlin547.athtem.eei.ericsson.se', 'secure_user': 'netsim', 'mim_version': '6.1.101', 'node_id': 'netsimlin547_LTE07ERBS00070', 'normal_password': 'netsim', 'security_state': 'ON', 'secure_password': 'netsim', 'identity': None, 'node_version': None, 'simulation': 'LTEF1101x160-RV-FDD-LTE07', 'subnetwork': 'SubNetwork=ERBS-SUBNW-1', 'revision': None, 'source_type': None}]
        self.assertTrue(len(node_parse.build_nodes(data_list, None, None)) == 0)

    def test_build_nodes_empty_data_list(self):
        data_list = [{'model_identity': '5783-904-386', 'primary_type': 'ERBS', 'normal_user': 'netsim', 'node_ip': '10.241.164.9', 'netsim': 'netsimlin547.athtem.eei.ericsson.se', 'secure_user': 'netsim', 'mim_version': '6.1.101', 'node_id': 'netsimlin547_LTE07ERBS00069', 'normal_password': 'netsim', 'security_state': 'ON', 'secure_password': 'netsim', 'identity': None, 'node_version': None, 'simulation': 'LTEF1101x160-RV-FDD-LTE07', 'subnetwork': 'SubNetwork=ERBS-SUBNW-1', 'revision': None, 'source_type': None}]
        self.assertTrue(len(node_parse.build_nodes(data_list, 0, 0)) == 0)

    def test_build_nodes_not_enough_data(self):
        data_list = [{'model_identity': '5783-904-386', 'primary_type': 'ERBS', 'normal_user': 'netsim', 'node_ip': '10.241.164.9', 'netsim': 'netsimlin547.athtem.eei.ericsson.se', 'secure_user': 'netsim', 'mim_version': '6.1.101', 'node_id': 'netsimlin547_LTE07ERBS00069', 'normal_password': 'netsim', 'security_state': 'ON', 'secure_password': 'netsim', 'identity': None, 'node_version': None, 'simulation': 'LTEF1101x160-RV-FDD-LTE07', 'subnetwork': 'SubNetwork=ERBS-SUBNW-1', 'revision': None, 'source_type': None}]
        self.assertTrue(len(node_parse.build_nodes(data_list, 3, 4)) == 0)

    @patch("nssutils.lib.exception.handle_invalid_argument")
    def test_check_node_range_in_result_file_throws_exception(self, mock_exception):
        mock_exception.side_effect = SystemExit("Exit Message")
        with self.assertRaises(SystemExit):
            node_parse.check_node_range_in_result_file(self.comecim_nodes_file, 1, 100)

        self.assertTrue(mock_exception.called)

    @patch("nssutils.lib.filesystem.does_file_exist")
    def test_get_lines_from_file_gen_raises_runtime_error_if_file_does_not_exist(self, mock_does_file_exist):
        mock_does_file_exist.return_value = False
        gen = node_parse.get_lines_from_file_gen(self.test_nodes_data_file)
        with self.assertRaises(RuntimeError) as _:
            gen.next()

    def test_get_lines_from_file_gen_returns_correct_line(self):
        get_lines_gen = node_parse.get_lines_from_file_gen(self.test_nodes_data_file)
        list_lines = []
        while True:
            try:
                list_lines.append(get_lines_gen.next())
            except StopIteration:
                break
        line = 'LTE01ERBS00001, 192.168.100.1, H.1.220, 17B-H.1.220, , , ON, CORBA|FTP|SFTP|SSH|TELNET|HTTP, , , , , , , , bmV0c2lt, bmV0c2lt, bmV0c2lt, bmV0c2lt, ERBS, 17B, http://192.168.100.1:80/em/index.html, LTEH1220-limx160-5K-FDD-LTE01, netsim.vts.com, SubNetwork=ERBS-SUBNW-1, , ,'
        self.assertTrue(line in list_lines)

    def test_create_parser_with_network_elements(self):
        parser = node_parse.Parser("xml_file", network_elements=['LTE01', 'LTE02'])
        self.assertEqual(parser.network_elements, ['LTE01', 'LTE02'])

    def test_create_parser_with_junk_network_elements(self):
        parser = node_parse.Parser("xml_file", network_elements="")
        self.assertEqual(parser.network_elements, [])

    def test_create_parser_without_network_elements(self):
        parser = node_parse.Parser("xml_file", [])
        self.assertEqual(parser.network_elements, [])

    def test_build_arne_parse_dict_returns_dict(self):
        parser = node_parse.Parser("xml_file", [])
        self.assertTrue(parser.arne_parse_dict)

    def test_get_xml_tree_for_nonexistant_file_raises_runtime_exception(self):
        parser = node_parse.Parser("xml_file", [])
        with self.assertRaises(RuntimeError):
            parser.get_xml_tree("non existant")

    def test_get_xml_tree_for_non_xml_file_raises_runtime_exception(self):
        parser = node_parse.Parser(self.filtered_nodes_file, [])
        with self.assertRaises(RuntimeError):
            parser.get_xml_tree(self.filtered_nodes_file)

    def test_get_element_list_returns_element_with_subnetwork(self):
        parser = node_parse.Parser(self.subnetwork_file, [])
        element_tree = parser.get_xml_tree(self.subnetwork_file)
        element_list = parser.get_element_list(element_tree)
        subnetwork = element_list[0][0]
        self.assertEqual(subnetwork, "NSSutils")

    def test_get_element_list_returns_element_without_subnetwork(self):
        parser = node_parse.Parser(self.no_subnetwork_file, [])
        element_tree = parser.get_xml_tree(self.no_subnetwork_file)
        element_list = parser.get_element_list(element_tree)
        subnetwork = element_list[0][0]
        self.assertEqual(subnetwork, "None")

    def test_get_element_list_sets_simulation_and_netsim(self):
        parser = node_parse.Parser(self.no_subnetwork_file, [])
        element_tree = parser.get_xml_tree(self.no_subnetwork_file)
        parser.get_element_list(element_tree)
        self.assertTrue(parser.netsim != "" and parser.simulation != "")

    def test_get_element_what_happens_on_near_empty_xml_tree(self):
        parser = node_parse.Parser(self.empty_file, [])
        element_tree = parser.get_xml_tree(self.empty_file)
        element_list = parser.get_element_list(element_tree)
        self.assertEquals(element_list, [])

    def test_parse_elements_returns_subset_of_elements(self):
        parser = node_parse.Parser(self.test_xml_file_with_ipv4_atttributes, ['netsimlin537_BR01ERBS00001'])
        result = parser.parse_data()
        self.assertEqual(len(result), 1)

    def test_parse_elements_returns_subset_of_elements_ipv6(self):
        parser = node_parse.Parser(self.test_xml_file_with_ipv6_atttributes, ['netsimlin537_LTE64ERBS00004'])
        result = parser.parse_data()
        self.assertEqual(len(result), 1)

    def test_parse_elements_returns_all_elements(self):
        parser = node_parse.Parser(self.test_xml_file_with_ipv4_atttributes, [])
        result = parser.parse_data()
        self.assertEqual(len(result), 5)

    def test_parse_elements_returns_all_elements_ipv6(self):
        parser = node_parse.Parser(self.test_xml_file_with_ipv6_atttributes, [])
        result = parser.parse_data()
        self.assertEqual(len(result), 2)

    def test_update_doesnt_add_subnetwork_if_property_set_to_true(self):
        parser = node_parse.Parser("blah", [])
        parsed_data = {"primary_type": "ERBS"}
        config.set_prop('skip_subnetwork_in_parsing', 'true')
        parser.update(parsed_data, "SubNetwork")
        self.assertEqual(parsed_data['subnetwork'], '')

    def test_update_adds_additional_data(self):
        parser = node_parse.Parser("blah", [])
        parsed_data = {"primary_type": "ERBS"}
        parser.update(parsed_data, "SubNetwork")
        self.assertTrue(parsed_data.has_key('subnetwork') and parsed_data.has_key('netsim_fqdn') and parsed_data.has_key('simulation') and parsed_data.has_key('invalid_fields'))

    def test_order_rearranges_data_dictionary(self):
        data = {'associated_site': 'MSBR01ERBS00001', 'time_zone': 'UTC', 'netconf': '22', 'snmp': '25161',
                'snmp_versions': 'v3', 'netsim_fqdn': 'netsimlin547.athtem.eei.ericsson.se', 'primary_type': 'SGSN',
                'normal_user': 'netsim', 'node_ip': '10.241.166.129', 'invalid_fields': '', 'secure_user': 'netsim',
                'mim_version': '', 'oss_model_identity': '', 'node_name': 'SGSN-15A-WPP-V502', 'node_version': '15A',
                'em_url': 'http://10.241.166.129:8888', 'identity': '', 'normal_password': 'netsim',
                'security_state': 'ON', 'simulation': 'CORE-ST-SGSN-WPP-15A-V5x5', 'revision': '',
                'secure_password': 'netsim', 'subnetwork': 'SubNetwork=NETSimW',
                'supported_protocols': 'CORBA|SFTP|SSH|Netconf|SNMP', 'snmp_community': 'public',
                'snmp_security_name': 'admin', 'snmp_authentication_method': '', 'snmp_encryption_method': '',
                'managed_element_type': '', 'group_data': '', 'source_type': '', 'cluster_ip': '1.2.3.4',
                'apnodeAIpAddress': '1.2.3.4', 'apnodeBIpAddress': '1.2.3.4'}
        ordered_data = collections.OrderedDict([('node_name', 'SGSN-15A-WPP-V502'), ('node_ip', '10.241.166.129'),
                                                ('mim_version', ''), ('oss_model_identity', ''), ('revision', ''),
                                                ('identity', ''), ('security_state', 'ON'),
                                                ('supported_protocols', 'CORBA|SFTP|SSH|Netconf|SNMP'),
                                                ('netconf', '22'), ('snmp', '25161'), ('snmp_versions', 'v3'),
                                                ('snmp_community', 'public'), ('snmp_security_name', 'admin'),
                                                ('snmp_authentication_method', ''), ('snmp_encryption_method', ''),
                                                ('normal_user', 'netsim'), ('normal_password', 'netsim'),
                                                ('secure_user', 'netsim'), ('secure_password', 'netsim'),
                                                ('primary_type', 'SGSN'), ('node_version', '15A'),
                                                ('em_url', 'http://10.241.166.129:8888'),
                                                ('simulation', 'CORE-ST-SGSN-WPP-15A-V5x5'),
                                                ('netsim_fqdn', 'netsimlin547.athtem.eei.ericsson.se'),
                                                ('subnetwork', 'SubNetwork=NETSimW'), ('managed_element_type', ''),
                                                ('group_data', ''), ('invalid_fields', ''), ('source_type', ''),
                                                ('associated_site', 'MSBR01ERBS00001'), ('time_zone', 'UTC'),
                                                ('cluster_ip', '1.2.3.4'), ('apnodeAIpAddress', '1.2.3.4'),
                                                ('apnodeBIpAddress', '1.2.3.4')])
        parser = node_parse.Parser("blah", [])
        result = parser.order(data)
        self.assertEqual(ordered_data, result)

    def test_parse_element_parses_row_data(self):
        parser = node_parse.Parser(self.subnetwork_file, [])
        element_tree = parser.get_xml_tree(self.subnetwork_file)
        element_list = parser.get_element_list(element_tree)
        managed_element = element_list[0][1]
        parsed_dict = parser.parse_element(managed_element)
        self.assertEqual(len(parsed_dict.keys()), len(parser.arne_parse_dict.keys()))

    def test_parse_element_with_missing_xpath(self):
        parser = node_parse.Parser(self.subnetwork_file, [])
        parser.arne_parse_dict = {
            "primary_type": ("bogus_xpath", "attribute"),
            "node_name": ("bogus_xpath", "attribute")
        }
        element_tree = parser.get_xml_tree(self.subnetwork_file)
        element_list = parser.get_element_list(element_tree)
        managed_element = element_list[0][1]
        parsed_dict = parser.parse_element(managed_element)
        self.assertTrue(parsed_dict["primary_type"] == "")

    def test_com_ecim_node_not_prefixed_with_netsim(self):
        parser = node_parse.Parser(self.comecim_xml_file, [])
        element_tree = parser.get_xml_tree(self.comecim_xml_file)
        element_list = parser.get_element_list(element_tree)
        managed_element = element_list[0][1]
        parsed_dict = parser.parse_element(managed_element)
        self.assertTrue(parsed_dict["node_name"] == "CE01ERBS00001")

    def test_erbs_node_prefixed_with_netsim(self):
        parser = node_parse.Parser(self.subnetwork_file, [])
        element_tree = parser.get_xml_tree(self.subnetwork_file)
        element_list = parser.get_element_list(element_tree)
        managed_element = element_list[0][1]
        parsed_dict = parser.parse_element(managed_element)
        self.assertTrue(parsed_dict["node_name"] == "netsimlin537_BR01ERBS00001")

    def test_erbs_nodes_not_prefixed_with_netsim_if_property_set_to_false(self):
        config.set_prop('add_netsim_host_to_node_name', 'false')
        parser = node_parse.Parser(self.subnetwork_file, [])
        element_tree = parser.get_xml_tree(self.subnetwork_file)
        element_list = parser.get_element_list(element_tree)
        managed_element = element_list[0][1]
        parsed_dict = parser.parse_element(managed_element)
        self.assertTrue(parsed_dict["node_name"] == "BR01ERBS00001")

    def test_weird_passwords_on_nodes(self):
        nodes_dict = {"netsimlin537_BR01ERBS00001": {"SECURE": base64.b64encode("csv_$%,p"), "NORMAL": base64.b64encode(",,,@@@~~~#")},
                      "netsimlin537_BR01ERBS00005": {"SECURE": base64.b64encode("thispersondoes,:)"), "NORMAL": base64.b64encode("whomakesapassword,withacommainit")}}
        parser = node_parse.Parser(self.test_xml_custom_username_password, [])
        result_elements = parser.parse_data()

        for element in result_elements:
            node_name = element["node_name"]
            if node_name in nodes_dict:
                self.assertEqual(element["secure_password"], nodes_dict[node_name]["SECURE"])
                self.assertEqual(element["normal_password"], nodes_dict[node_name]["NORMAL"])

    def test_weird_user_names_on_nodes(self):
        nodes_dict = {"netsimlin537_BR01ERBS00001": {"SECURE": base64.b64encode("name1,,,"), "NORMAL": base64.b64encode("name@#./,1")},
                      "netsimlin537_BR01ERBS00002": {"SECURE": base64.b64encode(",,,name2"), "NORMAL": base64.b64encode("**90123++=,")},
                      "netsimlin537_BR01ERBS00003": {"SECURE": base64.b64encode("?@tere,._"), "NORMAL": base64.b64encode("ericsson_01,")},
                      "netsimlin537_BR01ERBS00004": {"SECURE": base64.b64encode(r"lucozade,\\23"), "NORMAL": base64.b64encode(r"jh\\,lucozade")},
                      "netsimlin537_BR01ERBS00005": {"SECURE": base64.b64encode("sillyusername,:)"), "NORMAL": base64.b64encode("smileyfaces:):):)")}}
        parser = node_parse.Parser(self.test_xml_custom_username_password, [])
        result_elements = parser.parse_data()

        for element in result_elements:
            node_name = element["node_name"]
            if node_name in nodes_dict:
                self.assertEqual(element["secure_user"], nodes_dict[node_name]["SECURE"])
                self.assertEqual(element["normal_user"], nodes_dict[node_name]["NORMAL"])

    def test_skip_validation_returns_correctly(self):
        self.assertFalse(node_parse._skip_validation())
        config.set_prop('skip_validation', True)
        self.assertTrue(node_parse._skip_validation())

    @patch('nssutils.lib.log.logger.info')
    def test_write_csv_handles_none_type_verbose(self, mock_info):
        data = [[{1: 'string value', 2: None, 3: 2}]]
        node_parse.write_csv(data, self.test_file, verbose=True)
        self.assertTrue(mock_info.called)

    @patch('nssutils.lib.log.logger.info')
    def test_write_csv_handles_none_type(self, mock_info):

        class TestObject(object):
            pass

        c = TestObject()
        data = [[{1: 'string value', 2: None, 3: c}]]
        node_parse.write_csv(data, self.test_file, verbose=False)
        self.assertFalse(mock_info.called)

    @patch('__builtin__.open', read_data="data", new_callable=mock_open)
    @patch('nssutils.lib.filesystem.does_file_exist', return_value=True)
    @patch('nssutils.lib.node_parse.csv.DictReader')
    def test_get_node_data_raises_key_error(self, mock_reader, *_):
        mock_reader.return_value = [{"primary_type": 'RBS', "group_data": "Group=RNC01", "netsim_fdn": "netsim"}]
        self.assertRaises(KeyError, node_parse.get_node_data, "some_file")

    @patch('__builtin__.open', read_data="data", new_callable=mock_open)
    @patch('nssutils.lib.filesystem.does_file_exist', return_value=True)
    @patch('nssutils.lib.node_parse.csv.DictReader')
    def test_get_node_data_raises_runtime_error(self, mock_reader, *_):
        mock_reader.return_value = [{'node_name': "Node1", 'node_ip': "1.2.3.4", 'mim_version': "17A",
                                     'oss_model_identity': "11.22.33", 'security_state': 'ON', 'normal_user': object(),
                                     'normal_password': "pass", 'secure_user': "user", 'secure_password': "pass",
                                     'subnetwork': "NetW", 'invalid_fields': "", 'netconf': "111", 'snmp': "",
                                     'snmp_versions': "V1", 'snmp_community': "user", 'snmp_security_name': None,
                                     'snmp_authentication_method': "", 'snmp_encryption_method': "", 'revision': "",
                                     'identity': "", 'primary_type': "MLTN", 'node_version': "",
                                     'netsim_fqdn': "netsim", 'simulation': "", 'managed_element_type': "",
                                     'source_type': "", 'time_zone': "GMT", "group_data": "Group=RNC01"}]
        self.assertRaises(RuntimeError, node_parse.get_node_data, "some_file")

    @patch('__builtin__.open', read_data="data", new_callable=mock_open)
    @patch('nssutils.lib.filesystem.does_file_exist', return_value=True)
    @patch('nssutils.lib.node_parse.csv.DictReader')
    def test_get_node_data_builds_rnc_controller(self, mock_reader, *_):
        mock_reader.return_value = [{'node_name': "Node1", 'node_ip': "1.2.3.4", 'mim_version': "17A",
                                     'oss_model_identity': "11.22.33", 'security_state': 'ON', 'normal_user': "user",
                                     'normal_password': "pass", 'secure_user': "user", 'secure_password': "pass",
                                     'subnetwork': "NetW", 'invalid_fields': "", 'netconf': "111", 'snmp': "",
                                     'snmp_versions': "V1", 'snmp_community': "user", 'snmp_security_name': "user",
                                     'snmp_authentication_method': "", 'snmp_encryption_method': "", 'revision': "",
                                     'identity': "", 'primary_type': "RBS", 'node_version': "",
                                     'netsim_fqdn': "netsim", 'simulation': "", 'managed_element_type': "",
                                     'source_type': "", 'time_zone': "GMT", "group_data": "Group=RNC01"}]
        res = node_parse.get_node_data("some_file")
        self.assertEqual("netsim_RNC01", res[0].get('controlling_rnc'))

    def test_validate_on_missing_node_name(self):
        node_data = {"primary_type": "ECM", "node_ip": "1.2.3.4", "invalid_fields": ""}
        validate = node_parse.Validate(node_data, self.dups)
        validate.validate()
        self.assertTrue(validate.node_data.get("invalid_fields") == "node_name: key missing from properties.conf")

    def test_validate_on_missing_node_ip(self):
        node_data = {"primary_type": "STP", "node_name": "LTE01", "invalid_fields": ""}
        validate = node_parse.Validate(node_data, self.dups)
        validate.validate()
        self.assertTrue(validate.node_data.get("invalid_fields") == "node_ip: key missing from properties.conf")

    def test_validate_on_missing_invalid_fields(self):
        node_data = {"primary_type": "ECM", "node_name": "LTE01", "node_ip": "1.2.3.4"}
        validate = node_parse.Validate(node_data, self.dups)
        validate.validate()
        self.assertTrue(validate.node_data.get("invalid_fields") == "invalid_keys: key missing from properties.conf")

    def test_validate_on_empty_primary_type(self):
        node_data = {"primary_type": "", "node_name": "LTE01", "node_ip": "1.2.3.4", "invalid_fields": ""}
        validate = node_parse.Validate(node_data, self.dups)
        validate.validate()
        self.assertTrue("primary_type:empty field" in validate.node_data.get("invalid_fields"))

    def test_validate_on_empty_node_ip_if_cluster_ip_not_none(self):
        node_data = {"primary_type": "ECM", "node_name": "LTE01", "node_ip": "", "invalid_fields": "",
                     "cluster_ip": "1.2.3.5"}
        validate = node_parse.Validate(node_data, self.dups)
        validate.validate()
        self.assertTrue(validate.node_data.get("node_ip") == "1.2.3.5")

    @patch('nssutils.lib.node_parse.cache.has_key', return_value=True)
    @patch('nssutils.lib.node_parse.cache.get')
    def test_load_model_info_does_not_query_model_if_key_set(self, mock_get, *_):
        node_parse.load_model_info("ERBS")
        self.assertTrue(mock_get.called)

    @patch('nssutils.lib.node_parse.cache.has_key', return_value=False)
    @patch('nssutils.lib.node_parse.config.get_prop', return_value="Blah")
    @patch('nssutils.lib.node_parse.model_info.get_supported_model_info')
    @patch('nssutils.lib.node_parse.cache.set')
    def test_load_model_sets_model_in_cache(self, mock_set, mock_model_info, *_):
        response = Mock()
        self.model_dict["PT-2020"] = [response]
        mock_model_info.return_value = self.model_dict
        node_parse.load_model_info("PT-2020")
        self.assertTrue(mock_set.called)

    def test_validate_on_missing_primary_type(self):
        node_data = {"node_name": "LTE01", "node_ip": "", "invalid_fields": "",
                     "cluster_ip": "1.2.3.5"}
        parsed_data = [node_data]
        node_parse.validate(parsed_data, warn_validation_errors=True)
        self.assertTrue(node_data['invalid_fields'] == "primary_type: key missing from properties.conf")

    @patch('nssutils.lib.node_parse.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse._skip_validation", return_value=False)
    @patch("nssutils.lib.node_parse.IsiteValidate.validate")
    def test_validate_isite_node_calls_isite_validate(self, mock_validate, *_):
        node_data = {"primary_type": "SBG-IS", "node_name": "LTE01", "node_ip": "", "invalid_fields": "",
                     "cluster_ip": "1.2.3.5"}
        parsed_data = [node_data]
        node_parse.validate(parsed_data)
        self.assertTrue(mock_validate.called)

    @patch('nssutils.lib.node_parse.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse._skip_validation", return_value=False)
    @patch("nssutils.lib.node_parse.CppValidate.validate")
    def test_validate_cpp_node_calls_cpp_validate(self, mock_validate, *_):
        node_data = {"primary_type": "RNC", "node_name": "LTE01", "node_ip": "", "invalid_fields": "",
                     "cluster_ip": "1.2.3.5"}
        parsed_data = [node_data]
        node_parse.validate(parsed_data)
        self.assertTrue(mock_validate.called)

    @patch('nssutils.lib.node_parse.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse._skip_validation", return_value=False)
    @patch("nssutils.lib.node_parse.COMECIMValidate.validate")
    def test_validate_ecim_node_calls_ecim_validate(self, mock_validate, *_):
        node_data = {"primary_type": "ECM", "node_name": "LTE01", "node_ip": "", "invalid_fields": "",
                     "cluster_ip": "1.2.3.5"}
        parsed_data = [node_data]
        node_parse.validate(parsed_data)
        self.assertTrue(mock_validate.called)

    @patch('nssutils.lib.node_parse.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse._skip_validation", return_value=False)
    @patch("nssutils.lib.node_parse.Validate.validate")
    def test_validate_unknown_node_type_calls_validate(self, mock_validate, *_):
        node_data = {"primary_type": "RXI", "node_name": "LTE01", "node_ip": "", "invalid_fields": "",
                     "cluster_ip": "1.2.3.5"}
        parsed_data = [node_data]
        node_parse.validate(parsed_data)
        self.assertTrue(mock_validate.called)

    @patch('nssutils.lib.node_parse.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse._skip_validation", return_value=True)
    @patch("nssutils.lib.node_parse.Validate.validate")
    def test_validate_is_skipped_if_skip_validation_is_true(self, mock_validate, *_):
        node_data = {"primary_type": "STN", "node_name": "LTE01", "node_ip": "", "invalid_fields": "",
                     "cluster_ip": "1.2.3.5", "simulation": "CORE-SIU"}
        parsed_data = [node_data]
        node_parse.validate(parsed_data)
        self.assertFalse(mock_validate.called)

    @patch('nssutils.lib.node_parse.model_info.get_supported_model_info')
    @patch("nssutils.lib.node_parse._skip_validation", return_value=True)
    @patch("nssutils.lib.node_parse.COMECIMValidate.validate")
    def test_validate_handles_stp_primary_type(self, mock_validate, *_):
        node_data = {"primary_type": "STP", "node_name": "LTE01", "node_ip": "", "invalid_fields": "",
                     "cluster_ip": "1.2.3.5"}
        parsed_data = [node_data]
        node_parse.validate(parsed_data)
        self.assertFalse(mock_validate.called)

    @patch("nssutils.lib.node_parse.model_info.get_supported_model_info")
    @patch("nssutils.lib.node_parse._skip_validation", return_value=False)
    @patch("nssutils.lib.node_parse.Validate.validate")
    @patch("nssutils.lib.log.logger.warn")
    def test_validate_logs_validation_failures(self, mock_warn, *_):
        node_data = {"primary_type": "BSP", "node_name": "LTE01", "node_ip": "", "invalid_fields": "bad ip",
                     "cluster_ip": "1.2.3.5"}
        parsed_data = [node_data]
        node_parse.validate(parsed_data, warn_validation_errors=True)
        self.assertTrue(mock_warn.called)


if __name__ == "__main__":
    unittest2.main(verbosity=2)
