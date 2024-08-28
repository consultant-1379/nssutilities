#!/usr/bin/env python
import os
import pkgutil

import unittest2

from nssutils.lib import node_parse
from nssutils.tests import func_test_utils, test_fixture
from nssutils.tests.func_test_utils import func_dec

COMMON_TESTS_PATH = os.path.join(pkgutil.get_loader('nssutils').filename, 'tests')


class NodeParseAcceptanceTests(unittest2.TestCase):
    test_nodes_xml_dir = os.path.join(COMMON_TESTS_PATH, "etc", "network_nodes")

    @classmethod
    def setUpClass(cls):
        cls.fixture = test_fixture.AcceptanceTestFixture(cls)

    @classmethod
    def tearDownClass(cls):
        func_test_utils.module_tear_down(cls)

    def setUp(self):
        func_test_utils.setup(self)

    def tearDown(self):
        func_test_utils.tear_down(self)

    @func_dec("Node Parse Library", "Write all the elements to file")
    def test_create_csv_file_all_elements(self):
        nodes = []
        xml_file = os.path.join(self.test_nodes_xml_dir, "arne_xml_ipv4_attributes_new_mims.xml")
        csv_file = "/tmp/nodes"
        parsed_data = node_parse.parse(xml_file, verbose=False)
        validated_data = node_parse.validate(parsed_data)
        nodes.append(validated_data)
        node_parse.write_csv(nodes, csv_file)
        nodes = node_parse.read_csv(csv_file, None, None)
        self.assertEqual(len(nodes), 5)

    @func_dec("Node Parse Library", "Write only specified network elements to the file")
    def test_create_csv_file_network_elements(self):
        nodes = []
        xml_file = os.path.join(self.test_nodes_xml_dir, "arne_xml_ipv4_attributes_new_mims.xml")
        csv_file = "/tmp/nodes"
        elements = ['netsimlin537_NE01ERBS00004', 'netsimlin537_NE01ERBS00005']
        parsed_data = node_parse.parse(xml_file, network_elements=elements, verbose=False)
        validated_data = node_parse.validate(parsed_data)
        nodes.append(validated_data)
        node_parse.write_csv(nodes, csv_file)
        nodes = node_parse.read_csv(csv_file, None, None)
        self.assertEqual(len(nodes), 2)


if __name__ == '__main__':
    unittest2.main(verbosity=2)
