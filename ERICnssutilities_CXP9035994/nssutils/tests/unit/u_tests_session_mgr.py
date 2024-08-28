#!/usr/bin/env python
import datetime

import requests
import unittest2
from mock import Mock, patch

from nssutils.lib import cache, http, persistence, shell, timestamp
from nssutils.lib.deprecated import session_mgr
from nssutils.tests import unit_test_utils


class SessionMgrUnitTests(unittest2.TestCase):

    mock_login_output = '<!DOCTYPE html>\n<html>\n<head>\n    <title>ENM Login</title>\n    <meta charset="utf-8">\n    <meta http-equiv="Pragma" content="no-cache">\n    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">\n    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">\n    <!-- Hook for rest calls redirect - please do not touch this comment at all! -->\n    <meta name="viewport" content="width=device-width, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no">\n    <meta name="apple-mobile-web-app-capable" content="yes">\n    <meta name="apple-mobile-web-app-status-bar-style" content="black">\n\n    <link href="pages/login/favicon.ico" rel="icon" type="image/x-icon"/>\n    <link type="text/css" rel="stylesheet" href="index.css" media="all">\n\n    <script type="text/javascript" src="js/jQuery.js"></script>\n    <script type="text/javascript" src="js/main.js"></script>\n</head>\n<body>\n<div id="Container">\n    <div class="torLogin-Holder">\n        <div class="torLogin-Holder-inner">\n            <div class="torLogin-Holder-ericssonLogo"></div>\n            <div class="torLogin-Holder-nameWrap" id="loginTitle"><span class="torLogin-Holder-title">Ericsson Network Manager</span></div>\n            <form action="/login" name="loginForm" id="loginForm" class="torLogin-Holder-form" method="POST">\n\n                <div class="torLogin-Holder-inputWrap">\n                    <input type="text" id="loginUsername" name="IDToken1" autofocus="autofocus" value=""\n                           placeholder="Username"\n                           class="torLogin-Holder-loginUsername">\n\n                    <div class="torLogin-Holder-inputComposition">\n                        <input type="password" id="loginPassword" name="IDToken2" value="" placeholder="Password"\n                               class="torLogin-Holder-loginPassword">\n                        <button id="submit" type="submit" class="torLogin-Holder-formButton">\n                            <span class="torLogin-Holder-formButtonImage"></span>\n                        </button>\n                    </div>\n                    <div id="messagesBox" class="torLogin-Holder-messagesBox"></div>\n\n                    <div class="torLogin-Holder-passRemind"></div>\n                </div>\n            </form>\n            <p class="torLogin-Holder-notice" id="loginNotice"></p>\n            <p class="ebText_small torLogin-Holder-noticeText" id="loginNoticeText"></p>\n            <button class="torLogin-Holder-okButton" id="loginNoticeOk" type="button" onclick="noticeOkClicked()">OK</button>\n        </div>\n        <p class="torLogin-Holder-copy">\xa9 Ericsson AB 2013-2015 - All Rights Reserved</p>\n    </div>\n</div>\n</body>\n</html>'

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

    @patch("nssutils.lib.deprecated.session_mgr.verify_credentials")
    @patch("nssutils.lib.deprecated.session_mgr.Session.execute")
    @patch("requests.sessions.Session.post")
    def test_request_uses_previously_established_session(self, mock_post, mock_execute, mock_verify):
        cache.set("httpd-hostname", "enm.test.org")
        response = requests.Response()
        response.cookies.update({"iPlanetDirectoryPro": "blahBLAHblah"})
        mock_verify.return_value = True
        mock_post.return_value = response
        session_mgr.establish_session("boba", "fett")
        session_mgr.request({}, "boba")
        self.assertTrue(mock_execute.called)

    @patch("nssutils.lib.deprecated.session_mgr.Session.__init__")
    @patch("nssutils.lib.deprecated.session_mgr.verify_credentials")
    @patch("nssutils.lib.deprecated.session_mgr.does_session_exist")
    def test_establish_session_always_establishes_a_new_session_when_force_new_session_parameter_is_true(self, mock_does_session_exist, mock_verify, mock_new_session):
        mock_does_session_exist.return_value = True
        mock_verify.return_value = True
        mock_new_session.return_value = None

        session_mgr.establish_session("boba", "fett", force_new_session=True)

        self.assertTrue(mock_new_session.called)

    @patch("nssutils.lib.shell.run_local_cmd")
    def test_establish_cookies_raises_runtime_error_if_unable_to_get_apache_hostname(self, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(1, "ERROR", 9.82)
        s = session_mgr.Session("user", "pw")
        self.assertRaises(RuntimeError, s._establish_cookies)

    @patch("requests.sessions.Session.post")
    def test_establish_cookies_returns_false_if_cookie_not_found_in_response(self, mock_post):
        cache.set("httpd-hostname", "test.ericsson.se")
        mock_post.return_value = requests.Response()
        s = session_mgr.Session("jimmy", "secret")
        self.assertFalse(s._establish_cookies())

    @patch("requests.sessions.Session.post")
    def test_establish_cookies_returns_true_if_cookie_found_in_response(self, mock_post):
        cache.set("httpd-hostname", "test.ericsson.se")
        response = requests.Response()
        response.cookies.update({"iPlanetDirectoryPro": "blahBLAHblah"})
        mock_post.return_value = response
        s = session_mgr.Session("jimmy", "secret")
        self.assertTrue(s._establish_cookies())

    @patch("nssutils.lib.deprecated.session_mgr.Session._establish_cookies")
    @patch("nssutils.lib.deprecated.session_mgr.Session._merge_http_request")
    @patch("requests.sessions.Session.send")
    @patch("nssutils.lib.http.Response.log")
    def test_session_execute_returns_response_with_same_id_as_request(self, mock_response_log, mock_requests_send, mock_merge_http_request, mock_establish_cookies):
        http_request = http.Request("get", "http://url")
        mock_merge_http_request.return_value = True
        mock_requests_send.return_value = True
        mock_response_log.return_value = True
        mock_establish_cookies.return_value = True

        request_id = http_request.id
        s = session_mgr.Session("user", "pw")
        s.session = Mock()
        response = s.execute(http_request)
        response_id = response.id

        self.assertEquals(request_id, response_id)

    @patch("nssutils.lib.filesystem.does_file_exist")
    @patch("nssutils.lib.config.parse_conf_file")
    def test_credentials_sourced_from_prod_credentials_properties_file(self, mock_parse_conf_file, mock_does_file_exist):
        mock_does_file_exist.return_value = True
        mock_parse_conf_file.return_value = {"username": "george", "password": "washington"}
        self.assertEquals(("george", "washington"), session_mgr.load_credentials_from_props())

    @patch("nssutils.lib.filesystem.does_file_exist")
    @patch("nssutils.lib.config.parse_conf_file")
    def test_credentials_not_returned_from_incomplete_properties_file(self, mock_parse_conf_file, mock_does_file_exist):
        mock_does_file_exist.return_value = True
        mock_parse_conf_file.return_value = {"username": "george", "badkey": "washington"}
        self.assertEquals((), session_mgr.load_credentials_from_props())

    @patch("nssutils.lib.deprecated.session_mgr.Session.execute")
    @patch("requests.sessions.Session.post")
    def test_request_made_without_username_uses_admin_session(self, mock_post, mock_execute):
        cache.set("httpd-hostname", "test.ericsson.se")
        mock_post.return_value = requests.Response()
        session = session_mgr.Session("administrator", "BigSecret")
        persistence.set("permanent-enm-admin-session", session, 2)
        persistence.set("permanent-enm-admin-session-timeout", session, 2)
        session_mgr.request({})
        self.assertTrue(mock_execute.called)

    def test_request_using_inactive_session_raises_runtime_error(self):
        cache.set("httpd-hostname", "test.ericsson.se")
        persistence.set("permanent-enm-admin-session-timeout", 1, 2)
        self.assertRaises(RuntimeError, session_mgr.request, {})

    @patch("requests.sessions.Session.post")
    def test_request_using_timed_out_session_raises_runtime_error(self, _):
        cache.set("httpd-hostname", "test.ericsson.se")
        session = session_mgr.Session("administrator", "BigSecret")
        persistence.set("permanent-enm-admin-session", session, 2)
        self.assertRaises(RuntimeError, session_mgr.request, {})

    @patch("nssutils.lib.deprecated.enm_user.User")
    @patch("nssutils.lib.deprecated.session_mgr.verify_credentials")
    @patch("nssutils.lib.deprecated.session_mgr.Session.execute")
    @patch("requests.sessions.Session.post")
    def test_request_made_with_invalid_session_on_enm_side_reattempts_request_with_new_user_session(self, mock_post, mock_execute, mock_verify_credentials, mock_user):
        cache.set("httpd-hostname", "test.ericsson.se")
        mock_response = requests.Response()
        mock_response.output = self.mock_login_output
        mock_execute.return_value = mock_response
        mock_post.return_value = requests.Response
        mock_user.return_value = Mock()
        mock_verify_credentials.return_value = True
        session = session_mgr.Session("administrator", "BigSecret")
        persistence.set("permanent-enm-admin-session", session, 200)
        persistence.set("permanent-enm-admin-session-timeout", session, 200)
        session_mgr.request({})
        self.assertEqual(mock_execute.call_count, 2)

    @patch("nssutils.lib.deprecated.enm_user.User")
    @patch("nssutils.lib.deprecated.session_mgr.verify_credentials")
    def test_re_establish_session_re_establishes_both_admin_and_user_sessions_when_session_is_not_admin_session(self, mock_verify_credentials, mock_user):
        mock_verify_credentials.return_value = True
        mock_user_obj = Mock()
        mock_user.return_value = mock_user_obj

        session = session_mgr.Session('some_user', 'some_password', keep_password=False)
        session_mgr._re_establish_session(session, is_admin=False)
        self.assertTrue(mock_user_obj.create.called)  # Session automatically created when user created

    def test_get_apache_host_url_function_returns_correct_url(self):
        cache.set("httpd-hostname", "apache123")
        expected_host_url = "https://apache123"
        self.assertEquals(expected_host_url, cache.get_apache_url())

    @patch("nssutils.lib.persistence.set")
    @patch("nssutils.lib.persistence.get")
    @patch("nssutils.lib.persistence.has_key")
    def test_request_executes_if_persisted_session_and_timeout_are_valid(self, mock_persistence_has_key, mock_persistence_get, mock_persistence_set):
        session = Mock()
        request = Mock()
        mock_response = requests.Response()
        mock_response.rc = 200
        mock_response.output = "some value"
        session.execute.return_value = mock_response
        mock_persistence_has_key.return_value = True
        mock_persistence_get.return_value = session
        mock_persistence_set.return_value = 10
        session_mgr.request(request)
        self.assertTrue(session.execute.called)

    @patch("nssutils.lib.persistence.update_ttl")
    @patch("nssutils.lib.persistence.get")
    @patch("nssutils.lib.persistence.has_key")
    def test_request_raises_runtime_error_if_persisted_session_is_expired(self, mock_persistence_has_key, mock_persistence_get, mock_persistence_update_ttl):
        session = Mock()
        request = Mock()
        mock_persistence_has_key.side_effect = [False, True]
        mock_persistence_get.return_value = session
        mock_persistence_update_ttl.return_value = True
        self.assertRaises(RuntimeError, session_mgr.request, request)

    def test_request_removes_expired_persisted_key(self):
        request = Mock()
        with self.assertRaises(RuntimeError):
            session_mgr.request(request)

    @patch("nssutils.lib.deprecated.session_mgr.Session.execute")
    def test_request_raises_unauthorized_user_exception_when_rc_is_403(self, mock_session_execute):
        request = Mock()
        mock_response = requests.Response()
        mock_response.rc = 403
        mock_response.output = "403 Forbidden"
        persistence.set("permanent-enm-admin-session", session_mgr.Session("unAuthorizedUser", "TestPassw0rd"), -1)
        mock_session_execute.return_value = mock_response
        with self.assertRaises(session_mgr.UnauthorizedUserException):
            session_mgr.request(request)

    def test_is_session_valid_returns_true_if_session_has_not_timedout(self):
        session = session_mgr.Session("mock_username", "mock_password")
        session.last_command_time = timestamp.get_current_time() - datetime.timedelta(hours=0.5)
        session.time_established = timestamp.get_current_time() - datetime.timedelta(hours=5)
        self.assertTrue(session.is_session_valid())

    def test_is_session_valid_returns_false_if_session_has_timed_out_due_to_inactivity(self):
        session = session_mgr.Session("mock_username", "mock_password")
        session.last_command_time = timestamp.get_current_time() - datetime.timedelta(hours=1)
        session.time_established = timestamp.get_current_time() - datetime.timedelta(hours=5)
        self.assertFalse(session.is_session_valid())

    def test_is_session_valid_returns_false_if_session_has_timed_out_after_10_hours(self):
        session = session_mgr.Session("mock_username", "mock_password")
        session.time_established = timestamp.get_current_time() - datetime.timedelta(hours=10)
        session.last_command_time = timestamp.get_current_time() - datetime.timedelta(hours=1)
        self.assertFalse(session.is_session_valid())

if __name__ == "__main__":
    unittest2.main(verbosity=2)
