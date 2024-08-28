#!/usr/bin/env python
import unittest2
from mock import patch

from nssutils.lib import network, persistence, shell
from nssutils.tests import unit_test_utils


class NetworkUnitTests(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    @patch("nssutils.lib.shell.run_local_cmd")
    def test_is_host_pingable_returns_false_if_command_return_code_is_not_zero(self, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(1, "ERROR", .234)
        self.assertFalse(network.is_host_pingable("fake_host"))

    @patch("nssutils.lib.shell.run_local_cmd")
    def test_is_host_pingable_returns_true_if_command_return_code_is_zero(self, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(0, "PING", .234)
        self.assertTrue(network.is_host_pingable("fake_host"))

    def test_is_host_pingable_raises_value_error_when_host_parameter_is_none(self):
        self.assertRaises(ValueError, network.is_host_pingable, None)

    def test_is_host_pingable_raises_value_error_when_host_parameter_is_empty_string(self):
        self.assertRaises(ValueError, network.is_host_pingable, "")

    @patch("socket.gethostbyaddr")
    @patch("socket.getfqdn")
    def test_that_fqdn_is_persisted_if_retrieved_successfully(self, mock_getfqdn, _):
        mock_getfqdn.return_value = "test-host.example.org"
        self.assertFalse(persistence.has_key("test-host-fqdn"))
        network.get_fqdn("test-host")
        self.assertTrue(persistence.has_key("test-host-fqdn"))

    @patch("socket.gethostbyaddr")
    @patch("socket.getfqdn")
    def test_that_second_request_for_same_host_returns_persisted_value(self, mock_getfqdn, _):
        mock_getfqdn.return_value = "foobar987.blah.com"
        initial_fqdn = network.get_fqdn("test-host")
        mock_getfqdn.return_value = "foobar123.blah.com"
        self.assertEqual(initial_fqdn, network.get_fqdn("test-host"))

    def test_is_ipv4_address_private_returns_false_when_passed_an_invalid_ip_address_outside_the_172_range(self):
        self.assertFalse(network.is_ipv4_address_private('172.258.45.233'))

    def test_is_ipv4_address_private_returns_false_when_passed_an_valid_ip_address_outside_the_172_range(self):
        self.assertFalse(network.is_ipv4_address_private('172.10.45.233'))

    def test_is_ipv4_address_private_returns_true_when_passed_a_valid_ip_address_within_the_172_range(self):
        self.assertTrue(network.is_ipv4_address_private('172.20.45.233'))

    def test_is_ipv4_address_private_returns_true_when_passed_a_valid_ip_address_beginning_with_192_168(self):
        self.assertTrue(network.is_ipv4_address_private('192.168.2.67'))

    def test_is_ipv4_address_private_returns_false_when_passed_an_invalid_ip_address_beginning_with_127(self):
        self.assertFalse(network.is_ipv4_address_private('127.265.67.44'))

    def test_is_ipv4_address_private_returns_true_when_passed_a_valid_ip_address_beginning_with_127(self):
        self.assertTrue(network.is_ipv4_address_private('127.5.67.44'))

    def test_is_ipv4_address_private_returns_false_when_passed_an_invalid_private_ip_address(self):
        self.assertFalse(network.is_ipv4_address_private('253.32.225.222'))

    def test_is_valid_ip4_returns_false_when_passed_an_ip_starting_with_zero(self):
        self.assertFalse(network.is_valid_ipv4('0.329.225.25'))

    def test_is_valid_ip4_returns_false_when_passed_an_ip_outside_legit_addresses(self):
        self.assertFalse(network.is_valid_ipv4('256.32.225.300'))

    def test_is_valid_ip4_returns_true_when_passed_a_valid_ipv4_address(self):
        self.assertTrue(network.is_valid_ipv4('10.32.225.31'))

    def test_is_valid_ip4_returns_false_when_passed_an_empty_string(self):
        self.assertFalse(network.is_valid_ipv4(''))

    def test_is_valid_ip6_returns_false_when_passed_an_ip_outside_legit_addresses(self):
        self.assertFalse(network.is_valid_ipv6('fe80:250:250:250:56ff:fe00:fe00:fe00:81'))

    def test_is_valid_ip6_returns_true_when_passed_an_supported_ipv6_address(self):
        self.assertTrue(network.is_valid_ipv6('fe80::250:56ff:fe00:81'))

    def test_is_valid_ip6_returns_false_for_an_unsupported_ipv6_address_with_prefix_length(self):
        self.assertFalse(network.is_valid_ipv6('fe80::250:56ff:fe00:81/64'))

    def test_is_valid_ip6_returns_false_when_passed_an_empty_string(self):
        self.assertFalse(network.is_valid_ipv6(''))

    def test_is_multicast_ip4_returns_true_when_passed_a_valid_ipv4_address(self):
        self.assertTrue(network.is_multicast_ipv4('232.32.225.3'))

    def test_is_multicast_ip4_returns_false_when_passed_an_invalid_ipv4_address(self):
        self.assertFalse(network.is_multicast_ipv4('oct.32.225.3'))

    def test_is_multicast_ip4_returns_false_when_passed_an_inaccurate_ipv4_address(self):
        self.assertFalse(network.is_multicast_ipv4('222.32.225.3'))


if __name__ == "__main__":
    unittest2.main(verbosity=2)
