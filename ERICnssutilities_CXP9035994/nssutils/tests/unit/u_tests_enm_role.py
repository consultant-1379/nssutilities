#!/usr/bin/env python
import json

import responses
import unittest2
from mock import patch
from requests.exceptions import HTTPError

from nssutils.lib.enm_node import BaseNode
from nssutils.lib.enm_user_2 import CustomRole, EnmComRole, RoleCapability, Target
from nssutils.lib.exceptions import EnvironError
from nssutils.tests import unit_test_utils

URL = 'http://test.com'


class ENMRoleUnitTests(unittest2.TestCase):

    BASE_URL = "/oss/idm/rolemanagement/roles"
    FULL_URL = "{0}/".format(BASE_URL)
    USECASES_URL = "/oss/idm/rolemanagement/usecases"
    TARGET_GROUPS_URL = "/oss/idm/targetgroupmanagement/targetgroups"

    @responses.activate
    def setUp(self):
        unit_test_utils.setup()
        unit_test_utils.mock_admin_session()
        user = unit_test_utils.mock_enm_user(session_url=URL)

        responses.add(responses.GET, URL + self.USECASES_URL,
                      body=json.dumps([{
                          "application": "PM Initiation and Collection",
                          "resource": "pm_service",
                          "action": "create",
                          "description": "Allows to create Subscriptions to enable Performance Monitoring on the Network."
                      }, {
                          "application": "PM Initiation and Collection",
                          "resource": "pm_service",
                          "action": "read",
                          "description": "Allows to read information from Subscriptions / Processes."
                      }]),
                      status=200,
                      content_type='application/json')

        self.enm_role = EnmComRole("Unit_test_role", description='test-role', user=user)
        self.custom_role = CustomRole("Unit_test_role", capabilities=RoleCapability.get_role_capabilities_for_resource("cm_editor", user=user), description='test-role', user=user)

    def tearDown(self):
        unit_test_utils.tear_down()

    @responses.activate
    def test_create_raises_http_error_if_creation_fails(self):
        responses.add(responses.GET, URL + self.BASE_URL,
                      body=json.dumps([{
                          "name": "Unit_test_role",
                          "description": "test-role",
                          "type": "com",
                          "status": "ENABLED"
                      }]),
                      status=200,
                      content_type='application/json')

        responses.add(responses.POST, URL + self.BASE_URL,
                      body='Not Found',
                      status=404,
                      content_type='text/plain')
        responses.add(responses.GET, URL + self.TARGET_GROUPS_URL,
                      body=json.dumps([{
                          "name": "ALL",
                          "description": ""
                      }]),
                      status=200,
                      content_type='application/json')
        self.assertRaises(HTTPError, self.enm_role.create)

    @responses.activate
    def test_update_raises_http_error_if_update_fails(self):
        responses.add(responses.PUT, URL + self.enm_role.FULL_URL + self.enm_role.name,
                      body='Not Found',
                      status=404,
                      content_type='text/plain')
        self.assertRaises(HTTPError, self.enm_role.update)

    @responses.activate
    def test_delete_raises_http_error_if_delete_fails(self):
        responses.add(responses.DELETE, URL + self.enm_role.FULL_URL + self.enm_role.name,
                      body='Not Found',
                      status=404,
                      content_type='text/plain')
        self.assertRaises(HTTPError, self.enm_role.delete)

    @responses.activate
    def test_get_all_roles_raises_http_error_if_get_all_fails(self):
        responses.add(responses.GET, URL + self.enm_role.BASE_URL,
                      body='Not Found',
                      status=404,
                      content_type='text/plain')
        self.assertRaises(HTTPError, self.enm_role.get_all_roles, self.enm_role.user)

    @responses.activate
    def test_custom_role_update_raises_http_error_if_update_fails(self):
        responses.add(responses.GET, URL + self.enm_role.BASE_URL,
                      body=json.dumps([{
                          "name": "Unit_test_role",
                          "description": "test-role",
                          "type": "com",
                          "status": "ENABLED"
                      }]),
                      status=200,
                      content_type='application/json')
        responses.add(responses.PUT, URL + self.enm_role.FULL_URL + self.custom_role.name,
                      body='Not Found',
                      status=404,
                      content_type='text/plain')
        self.assertRaises(HTTPError, self.custom_role.update)


class ENMTargetunitTests(unittest2.TestCase):

    BASE = Target.BASE_URL
    UPDATE = Target.UPDATE_URL
    DELETE = Target.DELETE_URL
    UPDATE_ASSIGNMENT = Target.UPDATE_ASSIGNMENT_URL
    NAME = "U_tests_target"
    DESC = "Unit test target description"

    def setUp(self):
        unit_test_utils.setup()
        unit_test_utils.mock_admin_session()
        self.user = unit_test_utils.mock_enm_user(session_url=URL)
        self.create_as = unit_test_utils.mock_enm_user(session_url=URL)
        self.target = Target(name=self.NAME, description=self.DESC)

    def tearDown(self):
        unit_test_utils.tear_down()

    @responses.activate
    def test_create_target_raises_http_error(self):
        responses.add(responses.POST, URL + self.BASE,
                      body='Not Found',
                      status=404,
                      content_type='text/plain')
        self.assertRaises(HTTPError, self.target.create, create_as=self.user)

    @patch('nssutils.lib.log.logger.debug')
    @responses.activate
    def test_create_target_runs_successfully(self, mock_debug):
        responses.add(responses.POST, URL + self.BASE,
                      body='Success',
                      status=200,
                      content_type='text/plain')
        self.target.create(create_as=self.create_as)
        self.assertTrue(mock_debug.called)

    @responses.activate
    def test_update_target_raises_http_error(self):
        responses.add(responses.PUT, URL + self.UPDATE.format(target=self.NAME),
                      json={},
                      status=400,
                      content_type='text/html')
        description = "New Description"
        self.assertRaises(HTTPError, self.target.update, description, user=self.user)

    @responses.activate
    def test_update_target_assignment_raises_http_error(self):
        responses.add(responses.PUT, URL + self.UPDATE_ASSIGNMENT,
                      json={},
                      status=400,
                      content_type='text/html')
        self.assertRaises(HTTPError, self.target.update_assignment, [BaseNode()], user=self.user)

    @responses.activate
    def test_update_target_assignment_raises_environ_error(self, *_):
        self.assertRaises(EnvironError, self.target.update_assignment, [], user=self.user)

    @patch('nssutils.lib.log.logger.debug')
    @responses.activate
    def test_update_target_runs_successfully(self, mock_debug):
        responses.add(responses.PUT, URL + self.UPDATE.format(target=self.NAME),
                      body='Success',
                      status=200,
                      content_type='text/plain')
        description = "New Description"
        self.target.update(description=description, user=self.user)
        self.assertTrue(mock_debug.called)

    @responses.activate
    def test_delete_target_raises_http_error(self):
        responses.add(responses.DELETE, URL + self.DELETE.format(target=self.NAME),
                      body='Not Found',
                      status=404,
                      content_type='text/plain')
        self.assertRaises(HTTPError, self.target.delete, user=self.user)

    @patch('nssutils.lib.log.logger.debug')
    @responses.activate
    def test_delete_target_runs_successfully(self, mock_debug):
        responses.add(responses.DELETE, URL + self.DELETE.format(target=self.NAME),
                      body='Success',
                      status=200,
                      content_type='text/plain')
        self.target.delete(user=self.user)
        self.assertTrue(mock_debug.called)


if __name__ == "__main__":
    unittest2.main(verbosity=2)
