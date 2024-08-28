#!/usr/bin/env python
import json


import unittest2
from enmscripting.command.command import CommandOutput
from enmscripting.exceptions import InternalError
from enmscripting.terminal.terminal import TerminalOutput
from mock import Mock, patch

import requests
from requests.exceptions import HTTPError, RequestException

from nssutils.lib import cache, enm_user_2 as enm_user, persistence
from nssutils.lib.enm_user_2 import EnmRole
from nssutils.lib.exceptions import NoOuputFromScriptEngineResponseError
from nssutils.tests import unit_test_utils
from nssutils.tests.unit_test_utils import get_http_response

URL = 'http://locahost'


class EnmUserUnitTests2(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()
        unit_test_utils.mock_admin_session()
        self.user = unit_test_utils.mock_enm_user(session_url=URL)

        self.create_as = unit_test_utils.mock_enm_user(session_url=URL)

    def tearDown(self):
        unit_test_utils.tear_down()

    @patch('nssutils.lib.cache.get_apache_url')
    @patch('enmscripting.terminal.terminal.EnmTerminal.execute')
    def test_execute_on_terminal(self, execute_mock, mock_apache_url):
        expected = [u'FDN : NetworkElement=netsim_LTE01ERBS00160', u'', u'FDN : NetworkElement=netsim_LTE04ERBS00002', u'', u'FDN : NetworkElement=netsimlin547_LTE08ERBS00076', u'', u'FDN : NetworkElement=netsimlin547_LTE08ERBS00062', u'', u'', u'4 instance(s)']
        mock_apache_url.return_value = URL
        output = TerminalOutput(
            json_response=u'{"output":"FDN : NetworkElement=netsim_LTE01ERBS00160\\n\\nFDN : NetworkElement=netsim_LTE04ERBS00002\\n\\nFDN : NetworkElement=netsimlin547_LTE08ERBS00076\\n\\nFDN : NetworkElement=netsimlin547_LTE08ERBS00062\\n\\n\\n4 instance(s)\\n","v":"2"}',
            http_code=200,
            success=True)
        execute_mock.return_value = output
        res = self.user.enm_execute('cmedit get * NetworkElement', on_terminal=True)
        res._is_complete = True
        res._result_lines = expected
        self.assertEquals(res.get_output(), expected)

    @patch('nssutils.lib.cache.get_apache_url')
    @patch('enmscripting.command.command.EnmCommand.execute')
    def test_execute_on_command(self, execute_mock, mock_apache_url):
        expected = [u'FDN : NetworkElement=netsim_LTE01ERBS00160', u'FDN : NetworkElement=netsim_LTE04ERBS00002', u'FDN : NetworkElement=netsimlin547_LTE08ERBS00076', u'FDN : NetworkElement=netsimlin547_LTE08ERBS00062', u'4 instance(s)']
        mock_apache_url.return_value = URL
        output = CommandOutput(
            json_response=u'{"output":{"type":"group","_elements":[{"type":"text","value":"FDN : NetworkElement=netsim_LTE01ERBS00160"},{"type":"text","value":"FDN : NetworkElement=netsim_LTE04ERBS00002"},{"type":"text","value":"FDN : NetworkElement=netsimlin547_LTE08ERBS00076"},{"type":"text","value":"FDN : NetworkElement=netsimlin547_LTE08ERBS00062"},{"type":"text","value":"4 instance(s)"}]},"command":"cmedit get * NetworkElement","v":"1"}',
            http_code=200,
            success=True)
        execute_mock.return_value = output
        res = self.user.enm_execute('cmedit get * NetworkElement', on_terminal=False)
        res._is_complete = True
        self.assertEquals([g.value() for g in res.get_output()], expected)

    @patch('nssutils.lib.cache.get_apache_url')
    @patch('enmscripting.command.command.EnmCommand.execute')
    def test_execute_raises_exception_if_file_path_is_invalid(self, execute_mock, mock_apache_url):
        mock_apache_url.return_value = URL
        output = CommandOutput(
            json_response=u'{"output":{"type":"group","_elements":[{"type":"text","value":"FDN : NetworkElement=netsim_LTE01ERBS00160"},{"type":"text","value":"FDN : NetworkElement=netsim_LTE04ERBS00002"},{"type":"text","value":"FDN : NetworkElement=netsimlin547_LTE08ERBS00076"},{"type":"text","value":"FDN : NetworkElement=netsimlin547_LTE08ERBS00062"},{"type":"text","value":"4 instance(s)"}]},"command":"cmedit get * NetworkElement","v":"1"}',
            http_code=200,
            success=True)
        execute_mock.return_value = output
        with self.assertRaises(OSError):
            self.user.enm_execute('cmedit get * NetworkElement', file_in='/path/does/not/exist')

    def test_has_role_returns_true_if_role_present_in_users_list_of_roles(self):
        self.user.roles.add(EnmRole("ADMINISTRTOR", user=self.create_as))
        self.assertTrue(self.user.has_role_name("ADMINISTRTOR"))

    def test_has_role_returns_false_if_role_not_present_in_users_list_of_roles(self):
        self.assertFalse(self.user.has_role_name("ADMINISTRTOR"))

    def test_first_name_returns_true_if_set_as_empty_string(self):
        self.user = enm_user.User("TestUser", "T3stP4ssw0rd", first_name="")
        self.assertFalse(self.user.first_name == "")
        self.assertEquals(self.user.first_name, self.user.username)

    def test_last_name_returns_true_if_set_as_empty_string(self):
        self.user = enm_user.User("TestUser", "T3stP4ssw0rd", last_name="")
        self.assertFalse(self.user.last_name == "")
        self.assertEquals(self.user.last_name, self.user.username)

    # NOTE: Create and delete functionality is largely covered in the acceptance tests for this module
    # The tests below are purely for getting our code coverage up (pff..i know)
    @patch('time.sleep')
    @patch("nssutils.lib.enm_user_2.User.open_session")
    @patch("requests.sessions.Session.request")
    @patch('nssutils.lib.cache.get_apache_url')
    def test_successful_user_creation(self, mock_get_apache_host_url, mock_request, *_):
        mock_get_apache_host_url.return_value = "https://apache"
        response = Mock()
        response.status_code = 200
        response.stdout = "OUTPUT"
        response.text = 'SUCCESS'
        response.is_redirect = False

        response2 = Mock()
        response2.status_code = 200
        response2.stdout = "OUTPUT"
        response2.text = 'SUCCESS'
        response2.is_redirect = False

        mock_request.side_effect = [response, response2, response, response]

        self.user.create(create_as=self.create_as)

    @patch("enmscripting.private.session.ExternalSession.request")
    @patch('nssutils.lib.cache.get_apache_url')
    def test_delete_function_is_successful(self, mock_get_apache_host_url, mock_request):
        mock_get_apache_host_url.return_value = "https://apache"
        response = Mock()
        response.status_code = 204
        response.text = 'SUCCESS'

        mock_request.return_value = response

        self.user.delete(delete_as=self.create_as)

    @patch('nssutils.lib.cache.get_apache_url')
    @patch("requests.sessions.Session.request")
    def test_get_enm_user_information_returns_valid_user_if_response_is_ok(self, mock_request, mock_apache_url):
        mock_apache_url.return_value = URL
        response = Mock()
        response.status_code = 200
        response.text = '{"name": "testUser", "isMemberOf": "ADMINISTRATOR"}'
        response.is_redirect = False
        mock_request.return_value = response
        self.assertTrue(self.user.get_enm_user_information()["name"] == 'testUser')

    @patch("requests.sessions.Session.request")
    def test_get_enm_user_information_returns_none_if_response_is_not_ok(self, mock_session_mgr_request):
        mock_request = Mock()
        mock_request.ok = False
        mock_request.text = "BAD OUTPUT"
        mock_request.is_redirect = False
        mock_session_mgr_request.return_value = mock_request
        self.assertTrue(self.user.get_enm_user_information() is None)

    @patch("nssutils.lib.enm_user_2.User.is_session_established")
    @patch("nssutils.lib.enm_user_2.User.get_enm_user_information", return_value={'name': 'testUser', 'isMemberOf': 'ADMINISTRATOR'})
    def test_is_session_established_returns_true(self, *_):
        self.assertTrue(self.user.is_session_established())

    @patch("nssutils.lib.enm_user_2.User.open_session")
    @patch("nssutils.lib.enm_user_2.User.remove_session")
    @patch("nssutils.lib.enm_user_2.User.get_enm_user_information", side_effect=enm_user.NoStoredPasswordError)
    def test_is_session_established_returns_false(self, *_):
        self.assertFalse(self.user.is_session_established())

    @patch("requests.sessions.Session.request")
    @patch('nssutils.lib.cache.get_apache_url')
    def test_assign_to_roles_runs_successfully(self, mock_get_apache_host_url, mock_request):
        mock_get_apache_host_url.return_value = "https://apache"
        response = Mock()
        response.status_code = 200
        response.text = "OUTPUT"

        mock_request.return_value = response

        self.user.assign_to_roles([EnmRole("OPERATOR", user=self.create_as)], assign_as=self.create_as)

    @patch('nssutils.lib.cache.get_apache_url')
    @patch('enmscripting.terminal.terminal.EnmTerminal.execute')
    def test_execute_on_terminal_raises_internalerror(self, execute_mock, mock_apache_url):
        mock_apache_url.return_value = URL
        output = TerminalOutput(
            json_response=u'{"gibrish":""}',
            http_code=200,
            success=True)
        execute_mock.return_value = output
        res = self.user.enm_execute('cmedit get * NetworkElement', on_terminal=True)
        self.assertRaises(InternalError, res.get_output)

    @patch('nssutils.lib.enm_user_2.User._execute_cmd',
           side_effect=NoOuputFromScriptEngineResponseError("Failed", response=Mock()))
    def test_execute_on_terminal_raises_NoOuputFromScriptEngineResponseError(self, *_):
        self.assertRaises(NoOuputFromScriptEngineResponseError, self.user.enm_execute, 'cmedit get * NetworkElement',
                          on_terminal=True)

    @patch("enmscripting.private.session.ExternalSession.request")
    @patch('nssutils.lib.cache.get_apache_url')
    def test_safe_request_logs_to_user(self, mock_get_apache_host_url, mock_request):
        mock_get_apache_host_url.return_value = "https://apache"
        response = get_http_response("POST", "https://test.com", 402, "")
        mock_request.side_effect = RequestException('', response=response)
        self.user.safe_request = True
        self.user.request('POST', 'http://test.com')
        # The keys of the ERRORS dict should be all the status codes that occurred above 299.
        # 599 is the status code for exceptions raised during request
        self.assertEqual([599], self.user.ui_response_info[("POST", "http://test.com")]["ERRORS"].keys())

    @patch("requests.post")
    def test_verify_credentials_returns_false_if_cookie_not_found_in_response(self, mock_post):
        cache.set("httpd-hostname", "foo.bar.com")
        mock_post.return_value = requests.Response()
        self.assertFalse(enm_user.verify_credentials("bob", "password"))

    @patch("requests.post")
    def test_verify_credentials_returns_true_if_cookie_found_in_response(self, mock_post):
        cache.set("httpd-hostname", "foo.bar.com")
        response = requests.Response()
        response.cookies.update({"iPlanetDirectoryPro": "blahBLAHblah"})
        mock_post.return_value = response
        self.assertTrue(enm_user.verify_credentials("bob", "password"))

    def test_raise_for_status(self):
        response = Mock()
        response.status_code = 500
        message_prefix = "gibberish: "

        response.text = "This is Text"
        self.assertRaisesRegexp(HTTPError, "{0}{1}".format(message_prefix, response.text),
                                enm_user.raise_for_status, response, message_prefix)

        response.headers = {"content-type": "application/json"}

        user_message = "This is a test"
        response.json.return_value = {"key1": "value1", 'userMessage': user_message}
        self.assertRaisesRegexp(HTTPError, "{0}{1}".format(message_prefix, user_message),
                                enm_user.raise_for_status, response, message_prefix)

        response.json.return_value = {"key1": "value1"}
        self.assertRaisesRegexp(HTTPError, "{0}{1}".format(message_prefix, json.dumps(response.json.return_value)),
                                enm_user.raise_for_status, response, message_prefix)

    # Unit test should be in u_tests_cache but this module does not exist
    def test_get_apache_host_url_function_returns_correct_url(self):
        cache.set("httpd-hostname", "apache123")
        expected_host_url = "https://apache123"
        self.assertEquals(expected_host_url, cache.get_apache_url())

    def test_process_safe_request_correctly_process_first_successful_request(self):
        response = get_http_response("GET", "https://google.com", 200, "")
        self.user._process_safe_request(response)
        self.assertEqual(self.user.ui_response_info[("GET", "https://google.com")][True], 1)
        self.assertEqual(self.user.ui_response_info[("GET", "https://google.com")][False], 0)

    def test_process_safe_request_correctly_process_first_unsuccessful_request(self):
        response = get_http_response("GET", "https://google.com", 404, "Not Found")
        self.user._process_safe_request(response)
        self.assertEqual(self.user.ui_response_info[("GET", "https://google.com")][True], 0)
        self.assertEqual(self.user.ui_response_info[("GET", "https://google.com")][False], 1)

    def test_process_safe_request_correctly_processes_multiple_requests(self):
        response1 = get_http_response("GET", "https://google.com", 200, "")
        response2 = get_http_response("GET", "https://google.com", 404, "Not Found")
        response3 = get_http_response("GET", "https://google.com", 599, "On Fire")
        response4 = get_http_response("GET", "https://facebook.com", 400, "You spend too much time here")
        self.user._process_safe_request(response1)
        self.user._process_safe_request(response2)
        self.user._process_safe_request(response3)
        self.user._process_safe_request(response4)
        self.assertEqual(self.user.ui_response_info[("GET", "https://google.com")][True], 1)
        self.assertEqual(self.user.ui_response_info[("GET", "https://google.com")][False], 2)
        self.assertEqual(self.user.ui_response_info[("GET", "https://facebook.com")][True], 0)
        self.assertEqual(self.user.ui_response_info[("GET", "https://facebook.com")][False], 1)
        self.assertEqual(sorted(self.user.ui_response_info[("GET", "https://google.com")]["ERRORS"].keys()), [404, 599])
        self.assertEqual(sorted(self.user.ui_response_info[("GET", "https://facebook.com")]["ERRORS"].keys()), [400])

    def test_process_safe_request_removes_id_from_requests_ending_in_numbers_and_aggregate_appropriately(self):
        response1 = get_http_response("GET", "https://google.com/2341", 200, "")
        response2 = get_http_response("GET", "https://google.com/2314", 200, "")
        response3 = get_http_response("GET", "https://google.com/1233", 599, "On Fire")
        self.user._process_safe_request(response1)
        self.user._process_safe_request(response2)
        self.user._process_safe_request(response3)
        self.assertEqual(self.user.ui_response_info[("GET", "https://google.com/<id>")][True], 2)
        self.assertEqual(self.user.ui_response_info[("GET", "https://google.com/<id>")][False], 1)

    @patch('nssutils.lib.cache.get_apache_url', return_value="1.2.3.4")
    @patch('enmscripting.private.session.ExternalSession.open_session')
    @patch('enmscripting.private.session._AUTH_COOKIE_KEY', return_value="cookie")
    @patch('nssutils.lib.persistence.set')
    @patch('enmscripting.enmsession.EnmSession')
    @patch('nssutils.lib.log.logger.debug')
    @patch("enmscripting.private.session.ExternalSession.__new__")
    def test_open_session(self, mock_session, *_):
        session = Mock()
        session.cookies = {"iPlanetDirectoryPro": "cookie"}
        session.headers = {}
        mock_session.return_value = session
        user = enm_user.User(username="test", password="1234")
        user.keep_password = True
        user.persist = True
        user._session_key = Mock()
        user.open_session(reestablish=False, url=None)

    @patch('nssutils.lib.cache.get_apache_url', return_value="1.2.3.4")
    @patch('enmscripting.private.session.ExternalSession.open_session')
    @patch('enmscripting.private.session._AUTH_COOKIE_KEY', return_value="cookie")
    @patch('nssutils.lib.persistence.set')
    @patch('enmscripting.enmsession.EnmSession')
    @patch('nssutils.lib.log.logger.debug')
    @patch("enmscripting.private.session.ExternalSession.__new__")
    def test_open_session_and_reestablish_session(self, mock_session, *_):
        session = Mock()
        session.cookies = {"iPlanetDirectoryPro": "cookie"}
        session.headers = {}
        mock_session.return_value = session
        user = enm_user.User(username="test", password="1234")
        user.keep_password = True
        user.persist = False
        user._session_key = None
        user.open_session(reestablish=True, url="test.com")

    @patch('nssutils.lib.cache.get_apache_url', return_value="1.2.3.4")
    @patch('nssutils.lib.log.logger.debug')
    @patch("enmscripting.private.session.ExternalSession.__new__")
    def test_open_session_raises_exception(self, mock_session, *_):
        session = Mock()
        session.cookies = {"iPlanetDirectoryPro": "cookie"}
        session.headers = {}
        mock_session.return_value = session
        user = enm_user.User(username="test", password="1234")
        user.keep_password = False
        self.assertRaises(enm_user.NoStoredPasswordError, user.open_session, reestablish=True, url="test.com")


class EnmUserUnitTests2Credentials(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    # Moved here so the setup above could be simplified for the user
    @patch("enmscripting.private.session.ExternalSession.__new__")
    @patch("nssutils.lib.enm_user_2.verify_credentials")
    @patch("nssutils.lib.filesystem.does_file_exist")
    @patch('nssutils.lib.cache.get_haproxy_host')
    @patch('nssutils.lib.cache.get_apache_ip_url')
    @patch("nssutils.lib.enm_user_2._prompt_for_credentials")
    def test_user_is_prompted_for_credentials_if_no_credentials_props_files_are_found(self, mock_prompt_for_credentials, mock_get_apache_host_url, mock_get_haproxy_host, mock_does_file_exist, mock_verify, mock_session):
        session = Mock()
        session.cookies = {}
        session.cookies["iPlanetDirectoryPro"] = "Mock/Cookie"
        session.headers = {}
        mock_session.return_value = session
        mock_does_file_exist.return_value = False
        mock_verify.return_value = True
        test_credentials = ("saint", "patrick")
        mock_get_apache_host_url.return_value = "http://apache"
        mock_get_haproxy_host.return_value = 'apache'
        mock_prompt_for_credentials.return_value = test_credentials
        self.assertFalse(persistence.has_key("administrator_session"))
        enm_user.get_or_create_admin_user()
        self.assertTrue(persistence.has_key("administrator_session"))


if __name__ == "__main__":
    unittest2.main(verbosity=2)
