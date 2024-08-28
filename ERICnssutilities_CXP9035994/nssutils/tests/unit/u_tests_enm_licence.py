#!/usr/bin/env python
import datetime

import unittest2
from mock import Mock
from parameterizedtestcase import ParameterizedTestCase

from nssutils.lib import enm_licence
from nssutils.lib.enm_user_2 import User
from nssutils.tests import unit_test_utils


class EnmLicenceUnitTests(ParameterizedTestCase):
    def setUp(self):
        unit_test_utils.setup()

        unit_test_utils.get_mock(self, "nssutils.lib.enm_user_2.get_admin_user", return_value=User("test_user"))
        self.enm_cli_response = [
            u'',
            u'Capacity License Usage Info',
            u'License Name\tExpiry Date\tLimit\tUsage\tUsage Recorded\tVendor Info',
            u'FAT1023070\tMar 16 2026 23:59:59 GMT\t1000000\t0\tN/A\tRadio_Network_Base_Package_numberOf_5MHzSC',
            u'FAT1023151\tMar 16 2026 23:59:59 GMT\t1000000\t0\tN/A\tCore_Network_Base_Package_numberOf_kSAU'
        ]
        self.mock_enm_execute = unit_test_utils.get_mock(self, "nssutils.lib.enm_user_2.User.enm_execute", return_value=Mock(get_output=lambda: self.enm_cli_response))

    def tearDown(self):
        unit_test_utils.tear_down()

    def test_parse_licence_list(self):
        parsed_licences = list(enm_licence.parse_licence_list(self.enm_cli_response))
        expected_response = [
            {
                'Expiry Date': 'Mar 16 2026 23:59:59 GMT',
                'Usage Recorded': 'N/A',
                'Limit': '1000000',
                'Vendor Info': 'Radio_Network_Base_Package_numberOf_5MHzSC',
                'Usage': '0', 'License Name': 'FAT1023070'
            }, {
                'Expiry Date': 'Mar 16 2026 23:59:59 GMT',
                'Usage Recorded': 'N/A',
                'Limit': '1000000',
                'Vendor Info': 'Core_Network_Base_Package_numberOf_kSAU',
                'Usage': '0',
                'License Name': 'FAT1023151'
            }
        ]
        self.assertListEqual(expected_response, parsed_licences)

    def test_get_valid_licence_returns_valid_licence(self):
        erbs_mock_licence = {
            'Expiry Date': 'Mar 16 2026 23:59:59 GMT',
            'parsedDate': datetime.datetime(2026, 3, 16, 23, 59, 59),
            'Usage Recorded': 'N/A',
            'Limit': '1000000',
            'Vendor Info': 'Radio_Network_Base_Package_numberOf_5MHzSC',
            'Usage': '0',
            'License Name': 'FAT1023070'
        }
        mme_mock_licence = {
            'Expiry Date': 'Mar 16 2026 23:59:59 GMT',
            'parsedDate': datetime.datetime(2026, 3, 16, 23, 59, 59),
            'Usage Recorded': 'N/A',
            'Limit': '1000000',
            'Vendor Info': 'Core_Network_Base_Package_numberOf_kSAU',
            'Usage': '0',
            'License Name': 'FAT1023151'
        }
        self.assertDictEqual(erbs_mock_licence, enm_licence.get_valid_licence(node_type='ERBS'))
        self.assertDictEqual(mme_mock_licence, enm_licence.get_valid_licence(node_type='MME'))

    def test_get_valid_licence_returns_none_if_expired_substring_in_date(self):
        self.mock_enm_execute.return_value = Mock(get_output=lambda: [
            u'',
            u'Capacity License Usage Info',
            u'License Name\tExpiry Date\tLimit\tUsage\tUsage Recorded\tVendor Info',
            u'FAT1023070\tMar 16 2026 23:59:59 GMT (expired)\t1000000\t0\tN/A\tRadio_Network_Base_Package_numberOf_5MHzSC',
            u'FAT1023151\tMar 16 2026 23:59:59 GMT (expired)|t1000000\t0\tN/A\tCore_Network_Base_Package_numberOf_kSAU'
        ])
        self.assertIsNone(enm_licence.get_valid_licence())

    def test_zero_licences_returned(self):
        self.mock_enm_execute.return_value = Mock(get_output=lambda: [
            u'',
            u'No license found.'
        ])
        self.assertIsNone(enm_licence.get_valid_licence())

    def test_get_valid_licence_returns_none_for_expired_licence(self):
        with unit_test_utils.mock_datetime(2027, 3, 17, 13, 11):
            self.assertIsNone(enm_licence.get_valid_licence())

    def test_get_valid_licence_raises_assertion_error_for_invalid_node_type(self):
        self.mock_enm_execute.return_value = Mock(get_output=lambda: [
            u'',
            u'Capacity License Usage Info',
            u'License Name\tExpiry Date\tLimit\tUsage\tUsage Recorded\tVendor Info',
            u'FAT1023070\tMar 16 2026 23:59:59 GMT\t1000000\t0\tN/A\tgibberish',
            u'FAT1023151\tMar 16 2026 23:59:59 GMT\t1000000\t0\tN/A\tCore_Network_Base_Package_numberOf_kSAU'
        ])
        self.assertRaises(AssertionError, enm_licence.get_valid_licence, node_type='INVALID')

    def test_get_valid_licence_returns_none_if_vendor_info_is_incorrect(self):
        self.mock_enm_execute.return_value = Mock(get_output=lambda: [
            u'',
            u'Capacity License Usage Info',
            u'License Name\tExpiry Date\tLimit\tUsage\tUsage Recorded\tVendor Info',
            u'FAT1023070\tMar 16 2026 23:59:59 GMT\t1000000\t0\tN/A\tgibberish',
            u'FAT1023151\tMar 16 2026 23:59:59 GMT\t1000000\t0\tN/A\tCore_Network_Base_Package_numberOf_kSAU'
        ])

        self.assertIsNone(enm_licence.get_valid_licence(node_type='ERBS'))

    def test_get_valid_licence_handles_never_response_uppercase(self):
        self.mock_enm_execute.return_value = Mock(get_output=lambda: [
            u'',
            u'Capacity License Usage Info',
            u'License Name\tExpiry Date\tLimit\tUsage\tUsage Recorded\tVendor Info',
            u'FAT1023070\tNever\t1000000\t0\tN/A\tRadio_Network_Base_Package_numberOf_5MHzSC'
        ])

        erbs_mock_licence = {
            'Expiry Date': 'Never',
            'Usage Recorded': 'N/A',
            'Limit': '1000000',
            'Vendor Info': 'Radio_Network_Base_Package_numberOf_5MHzSC',
            'Usage': '0',
            'License Name': 'FAT1023070'
        }
        self.assertDictEqual(erbs_mock_licence, enm_licence.get_valid_licence(node_type='ERBS'))

    def test_get_valid_licence_handles_never_response_lowercase(self):
        self.mock_enm_execute.return_value = Mock(get_output=lambda: [
            u'',
            u'Capacity License Usage Info',
            u'License Name\tExpiry Date\tLimit\tUsage\tUsage Recorded\tVendor Info',
            u'FAT1023070\tnever\t1000000\t0\tN/A\tgibberish',
            u'FAT1023151\tnever\t1000000\t0\tN/A\tRadio_Network_Base_Package_numberOf_5MHzSC'
        ])
        erbs_mock_licence = {
            'Expiry Date': 'never',
            'Usage Recorded': 'N/A',
            'Limit': '1000000',
            'Vendor Info': 'Radio_Network_Base_Package_numberOf_5MHzSC',
            'Usage': '0',
            'License Name': 'FAT1023151'
        }
        self.assertDictEqual(erbs_mock_licence, enm_licence.get_valid_licence(node_type='ERBS'))


if __name__ == "__main__":
    unittest2.main(verbosity=2)
