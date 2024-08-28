#!/usr/bin/env python
import socket

import unittest2
from mock import Mock, patch

from nssutils.lib import cache, config
from nssutils.lib.exceptions import EnvironError
from nssutils.tests import unit_test_utils


class CacheUnitTests(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    @patch('nssutils.lib.cache.get_haproxy_host')
    @patch('socket.getaddrinfo')
    def test_get_apache_ip_url_returns_random_url(self, socket_patch, haproxy_patch):
        socket_patch.return_value = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('141.137.236.110', 443)),
                                     (10, 3, 0, '', ('2001:1b70:82a1:13a:0:656:5263:c', 443, 0, 0))]
        haproxy_patch.return_value = 'ieatenm5263-2.athtem.eei.ericsson.se'
        url = cache.get_apache_ip_url()
        self.assertTrue(url in ['https://141.137.236.110:443', 'https://[2001:1b70:82a1:13a:0:656:5263:c]:443'])

    @patch('nssutils.lib.cache.get_haproxy_host')
    @patch('socket.getaddrinfo')
    def test_get_apache_ip_url_returns_ipv4_random_url(self, socket_patch, haproxy_patch):
        socket_patch.return_value = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('141.137.236.110', 443)),
                                     (1, 1, 8, '', ('141.137.236.111', 443, 0, 0))]
        haproxy_patch.return_value = 'ieatenm5263-2.athtem.eei.ericsson.se'
        url = cache.get_apache_ip_url()
        self.assertTrue(url in ['https://141.137.236.111:443', 'https://141.137.236.110:443'])

    @patch('nssutils.lib.cache.get_haproxy_host')
    @patch('socket.getaddrinfo')
    def test_get_apache_ip_url_returns_ipv6_random_url(self, socket_patch, haproxy_patch):
        socket_patch.return_value = [(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_IP, '', ('2001:1b70:82a1:13a:0:656:5263:c', 443, 0, 0))]
        haproxy_patch.return_value = 'ieatenm5263-2.athtem.eei.ericsson.se'
        url = cache.get_apache_ip_url()
        self.assertTrue(url == 'https://[2001:1b70:82a1:13a:0:656:5263:c]:443')

    @patch('nssutils.lib.shell.run_cmd_on_ms')
    def test_get_haproxy_host_returns_hostname(self, run_cmd_on_ms_patch):
        res = Mock(rc=0, stdout='ieatenm5263-2.athtem.eei.ericsson.se')
        run_cmd_on_ms_patch.return_value = res
        self.assertEquals(cache.get_haproxy_host(), 'ieatenm5263-2.athtem.eei.ericsson.se')

    @patch('nssutils.lib.shell.run_cmd_on_ms')
    def test_get_haproxy_host_raises_runtimeerror(self, _):
        self.assertRaises(RuntimeError, cache.get_haproxy_host)

    def test_is_vnf_laf_returns_true_if_set(self):
        config.set_prop('VNF_LAF', '1.2.3.4')
        self.assertTrue(cache.is_vnf_laf())

    def test_is_vnf_laf_returns_False_when_key_not_found(self):
        if config.has_prop('VNF_LAF'):
            config.set_prop('VNF_LAF', '')
        self.assertFalse(cache.is_vnf_laf())

    def test_is_emp_returns_true_if_set(self):
        config.set_prop('EMP', '1.2.3.4')
        self.assertTrue(cache.is_emp())

    def test_is_emp_returns_False_when_key_not_found(self):
        if config.has_prop('EMP'):
            config.set_prop('EMP', '')
        self.assertFalse(cache.is_vnf_laf())

    @patch('nssutils.lib.config.load_credentials_from_props')
    def test_get_vnf_laf_credentials_raises_value_error_on_missing_credentials(self, mock_load_credentials_from_props):
        mock_load_credentials_from_props.return_value = None
        self.assertRaises(ValueError, cache.get_vnf_laf_credentials)

    @patch('nssutils.lib.shell.run_remote_cmd')
    def test_copy_cloud_user_ssh_private_key_file_to_emp_when_key_exists_already_success(self, run_remote_cmd_patch):
        response = Mock()
        response.rc = 0
        run_remote_cmd_patch.return_value = response
        self.assertTrue(cache.copy_cloud_user_ssh_private_key_file_to_emp())

    @patch('nssutils.lib.shell.run_local_cmd')
    @patch('nssutils.lib.shell.run_remote_cmd')
    @patch('nssutils.lib.log.logger.info')
    def test_copy_cloud_user_ssh_private_key_file_to_emp_when_copy_from_workload_vm_success(self, mock_info,
                                                                                            run_remote_cmd_patch,
                                                                                            run_local_cmd_patch):
        fail_response = Mock()
        fail_response.rc = 2
        success_response = Mock()
        success_response.rc = 0
        run_remote_cmd_patch.side_effect = [fail_response, success_response]
        run_local_cmd_patch.return_value = success_response
        self.assertTrue(cache.copy_cloud_user_ssh_private_key_file_to_emp())
        self.assertTrue(mock_info.called)

    @patch('nssutils.lib.shell.run_remote_cmd')
    @patch('nssutils.lib.shell.run_local_cmd')
    def test_copy_cloud_user_ssh_private_key_file_to_emp_when_copy_from_workload_vm_fails(self, run_local_cmd_patch,
                                                                                          run_remote_cmd_patch):
        response = Mock()
        response.rc = 2
        run_remote_cmd_patch.return_value = response
        run_local_cmd_patch.return_value = response
        self.assertRaises(EnvironError, cache.copy_cloud_user_ssh_private_key_file_to_emp)

    @patch('nssutils.lib.cache.shell.run_local_cmd')
    @patch('nssutils.lib.shell.run_remote_cmd')
    @patch('nssutils.lib.log.logger.info')
    def test_copy_cloud_user_ssh_private_key_file_to_emp_when_move_fails(self, mock_info,
                                                                         run_remote_cmd_patch,
                                                                         run_local_cmd_patch):
        fail_response = Mock()
        fail_response.rc = 2
        pass_response = Mock()
        pass_response.rc = 0
        run_remote_cmd_patch.side_effect = [fail_response, fail_response]
        run_local_cmd_patch.return_value = pass_response
        self.assertRaises(EnvironError, cache.copy_cloud_user_ssh_private_key_file_to_emp)
        self.assertTrue(mock_info.called)


if __name__ == "__main__":
    unittest2.main(verbosity=2)
