import getpass
import json
import os
import re
import time

from collections import defaultdict
from urlparse import urljoin, urlparse

import requests
from requests.models import Response, Request
from requests.exceptions import HTTPError, ConnectionError, RequestException

from enmscripting.enmsession import EnmSession
from enmscripting.private.session import ExternalSession, _AUTH_COOKIE_KEY

import cache
import config
import exception
import filesystem
import log
import persistence
from nssutils.lib.persistence import persistable
from headers import SECURITY_REQUEST_HEADERS, DELETE_SECURITY_REQUEST
from .exceptions import (RolesAssignmentError, PasswordDisableError, NoOuputFromScriptEngineResponseError,
                         SessionNotEstablishedException, EnmApplicationError, EnvironError)


SESSION_TIMEOUTS = ['loginUsername', '401 Authorization Required']
ADMINISTRATOR_IDENTIFIER = 'administrator'
SSO_URL = 'login'


class NoStoredPasswordError(Exception):
    pass


@persistable
class User(object):

    BASE_URL = '/oss/idm/usermanagement/users'
    USER_URL = '/oss/idm/usermanagement/users/{username}/'
    MODIFY_PRIVELEGES_URL = "/oss/idm/usermanagement/modifyprivileges"
    FORCE_PASSWORD_CHANGE_URL = urljoin(USER_URL, 'forcepasswordchange')
    CHANGE_PASSWORD_URL = urljoin(USER_URL, 'password')
    BASE_SESSION_URL = "/oss/sso/utilities/users/"
    GET_USER_PRIVILEGES_URL = "/oss/idm/usermanagement/users/{0}/privileges"

    _PERSISTENCE_KEY = '{username}_session'

    def __init__(self, username, password=None, first_name=None, last_name=None, email=None,
                 roles=(), description="", establish_session=True, keep_password=False, password_reset_disabled=True,
                 safe_request=False, is_default_admin=False, persist=True, status='enabled', **kwargs):
        """
        Load user constructor

        :param username: The user's username (str)
        :param password: The user's password (str)
        :param first_name: The user's first name (str)
        :param last_name: The user's last name (str)
        :param email: The user's email (str)
        :param roles: The openIDM security roles to which the user will be assigned (list)
        :param description: The user's description (str)
        :param establish_session: Establishes a session on ENM for the created username (bool)
        :param keep_password: Attaches password to a Session object for this ENM user so sessions can be re-established when they expire (bool)
        :param verbose: Flag controlling whether additional information is printed to console during execution (bool)
        :param suppress_output: Optional flag to toggle printing the command output to screen (bool)
        :param password_reset_disabled: Toggles whether or not to disable password reset after logging into ENM (bool)
        :param safe_request: Ignore all requests exception except MissingSchema, InvalidSchema, InvalidURL and logs them to this instance
        :param is_default_admin: Flag to indicate if the user to be persisted is the default admin user
        :param persist: bool indicating if the user instance should persist itself in memory.
            The reason behind this is, workload profiles store the user instances to teardown list;
            so we don't want to persist the users in 2 places which consumes lots of memory in redis

        :rtype: object `<enm_user.User>`
        """
        self.username = username
        self.password = password

        self.roles = set(EnmRole(role) if isinstance(role, basestring) else role for role in roles)

        self.first_name = first_name
        self.last_name = last_name

        if not self.first_name:
            self.first_name = username

        if not self.last_name:
            self.last_name = username

        self.email = email or "{0}@{1}".format(self.username, 'ericsson.com')
        self.description = description

        self.password_reset_disabled = password_reset_disabled
        self.establish_session = establish_session
        self.keep_password = keep_password
        self.safe_request = safe_request
        self.persist = persist
        self.status = status

        self.user_type = kwargs.pop('user_type', "enmUser")
        self.temp_password = kwargs.pop('temp_password', 'TempPassw0rd')
        self.nodes = kwargs.pop('nodes', [])
        self.enm_session = None
        self._session_key = kwargs.pop('_session_key', None)
        self.ui_response_info = kwargs.pop('ui_response_info', defaultdict(dict))
        self._persistence_key = kwargs.pop('_persistence_key', User._PERSISTENCE_KEY.format(
            username=ADMINISTRATOR_IDENTIFIER if is_default_admin else username))

    def __enter__(self):
        self.create()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            exception.process_exception()

        self.delete()

    def has_role_name(self, role):
        """
        Checks if this user instance has the specified role

        :type role: string
        :param role: The openIDM role to Checks
        :rtype: boolean
        :return: True if the user has the role in his or her list of roles
        """

        return role in set(role.name for role in self.roles)

    def get_missing_roles(self, required_roles):
        """
        returns any of the missing roles a user needs for an operation

        :type required_roles: list[string]
        :param required_roles: List of roles to check exist
        :rtype: set[string]
        :return: set of missing roles needed for the operation
        """

        user_role_names = set(role.name for role in self.get_roles())

        missing_roles = set(required_roles)
        if "ADMINISTRATOR" in user_role_names:
            missing_roles = set(role for role in required_roles if not (role.endswith("_Operator") or role.endswith("_Administrator") or role == "FIELD_TECHNICIAN"))

        for role in set(missing_roles):
            # If role ends with _Operator, the same application role name ending with _Administrator is also acceptable (_Operator is read-only, _Administrator is read-write)
            if role in user_role_names or role.replace("_Operator", "_Administrator") in user_role_names:
                missing_roles.remove(role)

        return missing_roles

    def get_enm_user_information(self):
        """
        Gets the user information from ENM

        :return: The user information or None
        :raises: RuntimeError
        """
        user_dict = None
        session = self.session or get_admin_user().session

        if not session:
            raise RuntimeError('No session found to make the get user request')
        headers_dict = SECURITY_REQUEST_HEADERS
        response = self.get(self.USER_URL.format(username=self.username), headers=headers_dict)

        if response.ok:
            log.logger.debug("Successfully fetched user information '{0}'. response = '{1}'".format(self.username, response.text))
            user_dict = json.loads(response.text)

        return user_dict

    def is_session_established(self, url=None):
        """
        Checks if this user instance exists in ENM

        :type url: string
        :param url: URL of the ENM server to check session against
        :rtype: boolean
        :return: True if the user exists in ENM
        """

        try:
            self.open_session(url=url)
            if self.session and self.get_enm_user_information():
                log.logger.debug("Verified that user '{0}' exists".format(self.username))
                return True
        except NoStoredPasswordError:
            self.remove_session()
        except (HTTPError, ConnectionError) as e:
            raise SessionNotEstablishedException("Unable to establish session for user %s. Exception: %s"
                                                 % (self.username, str(e)))

        return False

    def open_session(self, reestablish=False, url=None):
        """
        Open the session to ENM, it will try to reuse the existing cookie if there is one,
        otherwise it will actually try to login to the ENM application given the login
        credentials

        :param reestablish: bool that forces the session to be reestablished or not
        :type reestablish: bool
        :param url: FQDN Apache URL of the ENM system the session will be opened against.
        :type url: str

        :raises NoStoredPasswordError: if reestablish and keep_password is False
        """

        url = url or cache.get_apache_url()
        log.logger.debug(str('Using host %s to make connections' % url))
        session = ExternalSession(url)
        # Since we are using IP to connect to Ipv6, we have to update the Host header parameter
        # session.headers['Host'] = cache.get_haproxy_host()

        login = True
        if reestablish:
            log.logger.debug(str('Trying to RE-ESTABLISH a session to ENM for user "%s"' % self.username))
            if not self.keep_password:
                raise NoStoredPasswordError(
                    'Cannot RE-ESTABLISH session because we don\'t have password stored for user %s' % self.username)
        else:
            if self._session_key:
                log.logger.debug(str('Existing session cookie found for user "%s"' % self.username))
                session.cookies[_AUTH_COOKIE_KEY] = self._session_key
                login = False
        if login:
            log.logger.debug(str('Trying to login to ENM for user "%s"' % self.username))
            session.open_session(self.username, self.password)
            if not self.keep_password:
                self.password = None
            log.logger.debug(str('User "%s" successfully logged in ENM' % self.username))
            self._session_key = session.cookies[_AUTH_COOKIE_KEY]
            if self.persist:
                persistence.set(self._persistence_key, self, -1)

        self.enm_session = EnmSession(session)

    @property
    def session(self):
        return self.enm_session and self.enm_session._session or None

    @classmethod
    def get_usernames(cls, user=None):
        """
        Gets a list of all usernames for users created on ENM

        :trype user: enm_user_2.User
        :param user: user instance for issuing request
        :rtype: list of strings
        :return: True if the response returned a 200 OK
        """
        user = user or get_admin_user()
        response = user.get(cls.BASE_URL, headers=SECURITY_REQUEST_HEADERS)
        response.raise_for_status()
        return [user_dict["username"] for user_dict in response.json()]

    def remove_session(self):
        """
        Removes the session for this user from ENM

        :rtype: None

        """
        self.session.close_session()
        log.logger.debug(str('Successfully removed user session "%s"' % self.username))
        self.enm_session = None
        persistence.remove(self._persistence_key)

    def _execute_cmd(self, cmd, **kwargs):
        """
        Executes the given command on the enm's script engine

        :param cmd: command to run

        :rtype: `enmscripting.Response` object
        """

        on_terminal = kwargs.pop('on_terminal')
        timeout_seconds = kwargs.pop('timeout_seconds') if 'timeout_seconds' in kwargs else 600

        if on_terminal:
            execute = self.enm_session.terminal().execute
        else:
            execute = self.enm_session.command().execute

        return execute(cmd, timeout_seconds=timeout_seconds, **kwargs)

    def enm_execute(self, command, on_terminal=True, file_in=None, timeout_seconds=None):
        """
        Executes the given command on the enm's script engine

        :param command: command to run
        :type command: str
        :param on_terminal: bool to indicate if to run command using enmscripting terminal
        :type on_terminal: bool
        :param file_in: path to the file to use in the enm command
        :type file_in: str
        :param timeout_seconds: number of seconds to wait for command to respond
        :type timeout_seconds: int

        :raises SessionTimeoutException: raised if the session has timed out in ENM
        :raises NoOuputFromScriptEngineResponseError: raised if there is no response output

        :return: Response object returned by the command execution
        :rtype: `enmscripting.Response` object
        """

        if self.enm_session is None:
            self.open_session()

        if file_in and not os.path.isfile(file_in):
            raise OSError('File "%s" does not exist' % file_in)

        kwargs = {'on_terminal': on_terminal}

        if timeout_seconds:
            kwargs['timeout_seconds'] = int(timeout_seconds)

        file_obj = None
        if file_in:
            file_obj = kwargs['file'] = open(file_in, 'rb')
        mod_cmd = None
        if 'password' in command:
            mod_cmd = re.sub(r"password\s+\S+", "password ********", command)
        log.logger.debug("Executing ScriptEngine command '{0}' with file '{1}' ".format(mod_cmd[:1000] if mod_cmd else command[:1000], file_in))

        try:
            response = self._execute_cmd(command, **kwargs)
            if response.http_response_code() == 302:
                # We hit the redirection, since enmscripting is disabling the redirection for
                # all the requests, they won't have the actual redirection. So its fairly safe
                # to assume that we have hit the login page at this point. Also the response object
                # does not give the headers from which we can verify the location. So lets try
                # to login to the server again and rerun the command
                log.logger.debug(
                    "Redirected to ENM login. Response code of: '{0}' received from enmscripting - Therefore we will try to login again.".format(
                        response.http_response_code()))
                self.open_session(reestablish=True)
                if 'file' in kwargs:
                    kwargs['file'].seek(0, 0)
                log.logger.debug(
                    "Re-Executing ScriptEngine command '{0}' with file {1} ".format(command[:1000], file_in))
                response = self._execute_cmd(command, **kwargs)
        finally:
            if file_obj:
                file_obj.close()
            if config.has_prop('close_session') and config.get_prop('close_session') is True:
                self.session.close_session()
                log.logger.debug(str('Successfully closed user session "%s"' % self.username))
            self.enm_session._session.close()

        response.command = command
        if not response.is_command_result_available():
            raise NoOuputFromScriptEngineResponseError("No output to parse from ScriptEngineCommand {0}"
                                                       "".format(command[:1000]), response=response)

        return response

    def _log_for_status(self, response, ignore_status_lst=None):
        """Adds entry to failed_requests if status code is not valid in response
        :param response: `requests.models.Response` to log
        :param ignore_status_lst: bool indicating if we need to append this failed request to user
        """
        # We will always want to ignore 401s as these AuthorizationErrors are followed by the user trying to reestablish
        ignore_status_lst = ignore_status_lst or []
        ignore_status_lst.append(401)

        try:
            response.raise_for_status()
        except RequestException as e:
            log.logger.debug(
                str('%s request to "%s" failed with status code %s and response "%s"' % (
                    e.response.request.method, e.response.url, e.response.status_code, e.response.text)))
        else:
            log.logger.debug(str('%s request to "%s" was successful' % (
                response.request.method, response.request.url)))

        # How should we handle failed requests with status_code in ignore_status_lst?
        # I've chosen to ignore them for now as if the requests were never made but am open to suggestions
        if self.safe_request and response.status_code not in ignore_status_lst:
            self._process_safe_request(response)

    def _process_safe_request(self, response):
        """
        Adds information from a response to the ui_response_info dict for aggregation in the profile class

        :type response: requests.models.Response
        :param response: response object to process for ui_profiles
        """
        if response.request.url.split("/")[-1].isdigit():
            response.request.url = "/".join(response.request.url.split("/")[:-1] + ["<id>"])
        elif bool(re.search(r'\d', response.request.url)):
            response.request.url = re.sub(r"\d+", "[NUM]", response.request.url)
        request_key = (response.request.method, response.request.url)

        if request_key not in self.ui_response_info:
            self.ui_response_info[request_key][True] = 0
            self.ui_response_info[request_key][False] = 0

        self.ui_response_info[request_key][response.ok] += 1

        if not response.ok:
            if "ERRORS" not in self.ui_response_info[request_key]:
                self.ui_response_info[request_key]["ERRORS"] = {response.status_code: response}
            elif response.status_code not in self.ui_response_info[request_key]["ERRORS"]:
                self.ui_response_info[request_key]["ERRORS"][response.status_code] = response

    def _make_request(self, method, url, *args, **kwargs):
        """Sends a http request
        :param url: URL for the new :class:`Request` object.
        :param method: HTTP method
        :return: `Response` object
        """
        ignore_status_lst = kwargs.pop('ignore_status_lst', None)
        response = None
        try:
            response = self.session.request(method, url, *args, **kwargs)
        except RequestException as e:
            if not self.safe_request:
                raise

            response = e.response if e.response else _get_failed_response(method, url, e)

        self._log_for_status(response, ignore_status_lst=ignore_status_lst)

        return response

    def request(self, method, url, *args, **kwargs):
        """Sends a http request
        :param url: URL for the new :class:`Request` object.
        :param method: HTTP method
        :rtype: requests.Response
        :return: `Response` object
        """
        if self.enm_session is None:
            self.open_session()

        kwargs.setdefault('verify', False)
        if not urlparse(url).netloc:
            url = urljoin(self.session.url(), url)
        response = self._make_request(method, url, *args, **kwargs)

        if isinstance(response, Response) and any(x in response.text for x in SESSION_TIMEOUTS):
            log.logger.debug("ERROR: Session lost on application side. "
                             "Removing current session from persistence and trying to re-establish the session.")
            try:
                self.open_session(reestablish=True)
            except ValueError as e:
                raise EnmApplicationError("Unable to re-establish session for user %s. Exception: %s" % (self.username, str(e)))
            response = self._make_request(method, url, *args, **kwargs)
        return response

    def get(self, url, **kwargs):
        """Sends a GET request
        :param url: URL for the new :class:`Request` object.
        :return: `Response` object
        """
        return self.request('GET', url, **kwargs)

    def head(self, url, **kwargs):
        """Sends a HEAD request.
        :param url: URL for the new :class:`Request` object.
        :return: `Response` object
        """

        return self.request('HEAD', url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        """Sends a POST request.
        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param json: (optional) json to send in the body of the :class:`Request`.
        :return: `Response` object
        """

        return self.request('POST', url, data=data, json=json, **kwargs)

    def put(self, url, data=None, **kwargs):
        """Sends a PUT request.
        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :return: `Response` object
        """

        return self.request('PUT', url, data=data, **kwargs)

    def delete_request(self, url, **kwargs):
        """Sends a DELETE request
        :param url: URL for the new :class:`Request` object.
        :return: Response` object
        """

        return self.request('DELETE', url, **kwargs)

    def create(self, create_as=None):
        """
        Creates the user in ENM

        :param create_as: user instance to use for creating the new user.
        :rtype: bool
        :return: True if the response returned a 200 OK
        """
        create_as = create_as or get_admin_user()

        payload = {
            "username": self.username,
            "password": self.password,
            "status": self.status,
            "name": self.first_name,
            "surname": self.last_name,
            "email": self.email,
            "description": self.description,
            "passwordResetFlag": not self.password_reset_disabled,
            "privileges": []
        }

        for role in self.roles:
            for target in role.targets:
                payload["privileges"].append({
                    "role": role.name,
                    "targetGroup": target.name
                })

        response = create_as.post(self.BASE_URL, json=payload, headers=SECURITY_REQUEST_HEADERS)

        if response.status_code not in [200, 201]:
            raise HTTPError('User "{0}" with {1} roles failed to create. Reason "{2}"'.format(self.username, len(self.roles), response.json()["userMessage"]), response=response)

        log.logger.debug("Successfully created user {0} with role: {1}".format(self.username, ','.join(str(role) for role in self.roles)))

        if self.establish_session:
            # Bug where login invalid credentials exception raised if we don't sleep
            established = False
            for i in [1, 5, 10, 15, 20]:
                try:
                    time.sleep(i)
                    self.open_session()
                except ValueError as e:
                    log.logger.debug('Cannot login with the user {0}, after sleeping for {1} seconds. Trying again... Error Message was {2}'.format(self.username, i, str(e)))
                else:
                    established = True
                    break

            if not established:
                raise RuntimeError('Maximum retries reached. Cannot establish session for user %s' % self.username)
        else:
            # If we disabled the password reset for a user we created, we only want to raise a runtime error if we cannot login with that credentials.
            # Need to sleep temporarily to allow user to be created
            time.sleep(2)
            if self.password_reset_disabled and not verify_credentials(self.username, self.password, create_as.session.url()):
                raise RuntimeError("Unable to login with credentials username: {0} password: {1}".format(self.username, self.password))

    def delete(self, delete_as=None):
        """
        Deletes the user from ENM

        :param delete_as: user instance to use for deleting this user.
        :return: True if the response returned a 200 OK
        """

        delete_as = delete_as or get_admin_user()

        url = self.USER_URL.format(username=self.username)
        try:
            response = delete_as.delete_request(url, headers=DELETE_SECURITY_REQUEST)
        except ValueError as e:
            log.logger.debug(e.message)
        if response.status_code != 204:
            raise HTTPError('Unable to delete user %s. Reason "%s"' % (self.username, response.text), response=response)

        if self.session:
            self.remove_session()
        else:
            persistence.remove(self._persistence_key)

    def assign_to_roles(self, roles=None, assign_as=None):
        """
        Assigns a user to one or many roles

        :param assign_as: user instance to use for assigning roles to this user.
        :param roles: List of openIDM roles in which to assign the user to
        :return: True if the response from each role update returned a 200 OK
        """

        roles = roles or self.roles
        assign_as = assign_as or get_admin_user()

        log.logger.debug("Assigning user {0} to roles {1}".format(self.username, log.purple_text(roles)))

        payload = [{
            "action": "ADD",
            "user": self.username,
            "targetGroup": "ALL",
            "role": role} for role in roles]

        response = assign_as.put(
            self.MODIFY_PRIVELEGES_URL,
            json=payload, headers=SECURITY_REQUEST_HEADERS,
            verify=False, timeout=60)

        if response.status_code not in [200, 201]:
            log.logger.debug("Unable to assign roles {0} to user {1}".format(roles, self.username))
            log.logger.debug("    Output: {0}".format(response.text))
            raise RolesAssignmentError(
                'Unable to assign roles "%s" to user "%s". Reason "%s"' % (
                    ','.join(roles), self.username, response.text),
                response=response)

        log.logger.debug(str('Successfully assigned roles "%s" to user "%s"' % (','.join(role.name for role in roles),
                                                                                self.username)))

    def set_status(self, status, assign_as=None):
        """
        Toggle the status of the user passed in

        :param status: new status for user (string). e.g. enabled or disabled
        :param assign_as: : user instance to carry out request with (EnmUser)
        :return: None
        """

        assign_as = assign_as or get_admin_user()

        log.logger.debug("Changing status to {0} for user {1}".format(log.purple_text(status), self.username))

        payload = {"username": self.username, "status": status, "name": self.first_name,
                   "surname": self.last_name, "email": self.email}

        response = assign_as.put(self.USER_URL.format(username=self.username),
                                 json=payload, headers=SECURITY_REQUEST_HEADERS)

        if response.status_code not in [200, 201]:
            raise HTTPError('Unable to change status to "%s". Reason "%s"' % (status, response.text), response=response)

        log.logger.debug(str('Successfully changed status of user "%s" to "%s"' % (self.username, status)))

    def _teardown(self):
        self.delete()

    def change_password(self, change_as=None):
        change_as = change_as or get_admin_user()

        log.logger.debug(str('Trying to change password for user %s' % self.username))

        response = change_as.put(
            self.CHANGE_PASSWORD_URL.format(username=self.username),
            json={"oldPassword": self.temp_password, "password": self.password},
            headers=SECURITY_REQUEST_HEADERS)
        if response.status_code != 204:
            raise PasswordDisableError('Cannot change the password for user %s. Reason "%s"' % (self.username, response.text), response=response)

        log.logger.debug(str('Successfully changed password reset for user %s' % self.username))

    def get_roles(self):
        """
        Gets all the roles assigned to the user
        :rtype: set[EnmRole]
        """
        response = self.get(User.GET_USER_PRIVILEGES_URL.format(self.username), headers=SECURITY_REQUEST_HEADERS)
        if not response.ok:
            raise HTTPError('Unable to retrieve user privileges. Reason "%s"' % response.text, response=response)
        role_and_targets = defaultdict(list)
        for role_definition in response.json():
            role_and_targets[role_definition["role"]].append(role_definition["targetGroup"])

        return set([EnmRole(name, targets=targets, user=self.username) for name, targets in role_and_targets.iteritems()])

    def __setstate__(self, state):
        for attr, val in state.iteritems():
            setattr(self, attr, val)
        self.enm_session = None


def get_user_privileges(username):
    """
    Gets all the privileges assigned to a username
    @type username: string
    @param username: ENM username

    :rtype: set[EnmRole]
    """
    response = get_or_create_admin_user().get(User.GET_USER_PRIVILEGES_URL.format(username), headers=SECURITY_REQUEST_HEADERS)
    if not response.ok:
        raise HTTPError('Unable to retrieve user privileges. Reason "%s"' % response.text, response=response)

    role_and_targets = defaultdict(list)
    for role_definition in response.json():
        role_and_targets[role_definition["role"]].append(role_definition["targetGroup"])

    return set([EnmRole(name, targets=targets) for name, targets in role_and_targets.iteritems()])


def get_all_sessions():
    """
    Gets all the users currently logged into ENM

    :return: json dictionary {user_name: number_of_sessions}
    """
    response = get_or_create_admin_user().get(User.BASE_SESSION_URL, headers=SECURITY_REQUEST_HEADERS)
    if response.status_code not in [200, 201]:
        raise HTTPError('Unable to retrieve active sessions. Reason "%s"' % response.text, response=response)

    return response.json()


def get_or_create_admin_user(enm_admin_creds_file=None, open_session=True, initial_prompt="\nPlease enter the credentials of the ENM account to use", username_prompt="Username: ", password_prompt="Password: "):
    """
    Creates the admin user, opens enm session and persists the user for later use;
    Reads credentials file or prompts user on the terminal in production environs.
    Should only be called from the tool level.

    :return: `User` instance
    """
    if enm_admin_creds_file is None:
        enm_admin_creds_file = "/tmp/nssutils/enm-credentials"

    try:
        admin_user = get_admin_user(check_session=True)
    except:
        keep_password = True
        if filesystem.does_file_exist(enm_admin_creds_file):
            credentials = filesystem.get_lines_from_file(enm_admin_creds_file)
        else:
            credentials = config.load_credentials_from_props()
            # If we didn't find any file-based credentials, prompt for them
            if not credentials:
                keep_password = False
                credentials = _prompt_for_credentials(initial_prompt, username_prompt, password_prompt)

        # Bail if we don't appear to have valid data
        if credentials is None or len(credentials) != 2:
            raise RuntimeError("Unable to obtain ENM SECURITY_ADMIN credentials")

        admin_user = User(credentials[0], credentials[1], keep_password=keep_password, is_default_admin=True)
        if not open_session and persistence.get('administrator_session') is not None:
            return admin_user
    admin_user.open_session()

    return admin_user


def _prompt_for_credentials(initial_prompt, username_prompt, password_prompt):
    """
    B{Prompts the operator for the username and password of an ENM user account with the SECURITY_ADMIN role}

    :type initial_prompt: string
    :type username_prompt: string
    :type password_prompt: string
    @rtype: tuple
    @return: 2-element tuple consisting of (username, password)
    """

    log.logger.info(initial_prompt)
    time.sleep(0.1)
    username = raw_input(username_prompt)
    password = getpass.getpass(password_prompt)
    print
    return username, password


def get_admin_user(check_session=False):
    """
    Gets the admin user instance from persistence

    :raises: RuntimeError if admin does not exist
    :rtype: User
    :return: `User` instance
    """
    admin_key = User._PERSISTENCE_KEY.format(username=ADMINISTRATOR_IDENTIFIER)
    if not is_session_available(admin_key, check_session):
        raise RuntimeError('Administrator session not established')
    return persistence.get(admin_key)


def is_session_available(user_key=None, check_session=False):
    """

    :type user_key: str
    :param user_key: String representation of the user key in persistence
    :type check_session: bool
    :param check_session: Boolean indicator, to determine whether or not to check if the session is still available

    :rtype: bool
    :return: boolean if the session is still available
    """
    user_key = user_key or User._PERSISTENCE_KEY.format(username=ADMINISTRATOR_IDENTIFIER)
    if persistence.has_key(user_key):
        user = persistence.get(user_key)
        if user.is_session_established() if check_session else True:
            return True


def _get_failed_response(method, url, e):
    """
    Returns default failed response object for exceptions that raise errors

    :type method: string
    :param method: type of request made (either post, put, delete or ger)
    :type url: string
    :param url: rest endpoint request was issued to

    :returns: 'Response' Instance
    """

    response = Response()
    response.status_code = 599
    response.url = url
    response._content = "NSSUtils response - ERROR: {0}\n{1} request to {2} raised this exception.".format(
        str(e), method, url
    )
    response.request = Request()
    response.request.method = method
    response.request.url = url
    return response


def verify_credentials(username, password, enm_url=None):
    """
    B{Determines whether ENM account credentials are valid or not}

    @type username: string
    @param username: ENM username
    @type password: string
    @param password: Password for specified username
    @type enm_url: string
    @param enm_url: URL of the ENM HTTP server that the credentials are to be verified against
    @rtype: boolean
    """
    result = False

    # Format the request payload and then POST it
    payload = {"IDToken1": username, "IDToken2": password}
    enm_url = enm_url or cache.get_apache_url()
    r = requests.post(urljoin(enm_url, SSO_URL), params=payload, verify=False, allow_redirects=False)

    if r.cookies is not None and "iPlanetDirectoryPro" in str(r.cookies):
        result = True

    return result


def raise_for_status(response, message_prefix=None):
    if 400 <= response.status_code < 600:
        if response.headers.get("content-type") == "application/json":
            try:
                message = response.json()
                if "userMessage" in message:
                    message = message["userMessage"]
                else:
                    message = json.dumps(message)
            except ValueError as e:
                message = str(e)
        else:
            message = response.text

        raise HTTPError(message_prefix + message, response=response)


class RolesUpdateError(Exception):
    pass


@persistable
class EnmRole(object):

    BASE_URL = "/oss/idm/rolemanagement/roles"
    FULL_URL = "{0}/".format(BASE_URL)
    USECASES_URL = "/oss/idm/rolemanagement/usecases"

    def __init__(self, name, description="", enabled=True, user=None, targets=None):
        """
        Constructor for ENM System Role object

        :type name: string
        :type description: string
        :type enabled: bool
        :type user: enm_user.User object
        """
        self.name = name
        self.description = description
        self.targets = targets if targets is not None else {Target("ALL")}
        self.enabled = enabled
        self.user = user or get_admin_user()

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        return str(self)

    def _teardown(self):
        """
        Secret teardown method
        """
        self._delete()

    def _create(self, additional_json=None):
        create_as = self.user or get_admin_user()

        existing_targets = Target.get_existing_targets(user=self.user)
        for target in self.targets:
            if target not in existing_targets:
                target.create(self.user)

        body = {
            "name": self.name,
            "description": self.description,
            "status": "ENABLED",
        }

        if additional_json:
            body.update(additional_json)

        response = create_as.post(self.BASE_URL, json=body, headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not create role: ")

    def _delete(self):
        """
        Deletes a Role on ENM

        :raises: HTTPError
        """
        response = self.user.delete_request(self.FULL_URL + self.name, headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not delete role: ")
        log.logger.debug("Successfully deleted ENM Role {0}".format(self.name))

    def _update(self, additional_json):
        body = {
            "type": "custom",
            "name": self.name,
            "description": self.description,
            "status": "ENABLED" if self.enabled else "DISABLED"
        }

        if additional_json:
            body.update(additional_json)

        response = self.user.put(self.FULL_URL + self.name, json=body, headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not update role: ")
        log.logger.debug("Successfully updated ENM Role {0}".format(self.name))

    @classmethod
    def get_role_by_name(cls, name, user=None):
        user = user or get_admin_user()
        response = user.get(cls.FULL_URL + name, headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not get ENM roles: ")
        role_info = response.json()

        if role_info["type"] in ["system", "application"]:
            return EnmRole(role_info["name"], description=role_info["description"], enabled=role_info["status"] == "ENABLED", user=user)
        elif role_info["type"] == "com":
            return EnmComRole(role_info["name"], description=role_info["description"], enabled=role_info["status"] == "ENABLED", user=user)
        else:
            sub_roles = set(EnmComRole(sub_role["name"], description=sub_role["description"], enabled=sub_role["status"] == "ENABLED", user=user) for sub_role in role_info["roles"])
            if role_info["type"] == "comalias":
                return EnmRoleAlias(role_info["name"], sub_roles, description=role_info["description"], enabled=role_info["status"] == "ENABLED", user=user)
            else:
                capabilities = set(RoleCapability(resource, action, user=user) for resource, actions in role_info["policy"].iteritems() for action in actions)
                return CustomRole(role_info["name"], sub_roles, capabilities, description=role_info["description"], enabled=role_info["status"] == "ENABLED", user=user)

    @classmethod
    def get_all_roles(cls, user=None):
        """
        :type role_types: list
        :type roles_to_add: list
        :raises: HTTPError
        :rtype: list
        :rtype: list of dicts, containing enm roles
        """
        user = user or get_admin_user()
        response = user.get(cls.BASE_URL, headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not get ENM roles: ")

        roles = set()
        for role_info in response.json():
            if role_info["type"] == "system":
                role = EnmRole(role_info["name"], description=role_info["description"], enabled=role_info["status"] == "ENABLED", user=user)
            elif role_info["type"] == "com":
                role = EnmComRole(role_info["name"], description=role_info["description"], enabled=role_info["status"] == "ENABLED", user=user)
            else:
                role = cls.get_role_by_name(role_info["name"], user=user)

            roles.add(role)
        return roles


@persistable
class EnmComRole(EnmRole):
    def __init__(self, name, targets=None, description="", enabled=True, user=None):
        """
        :type name: string
        :type targets: set[Target]
        :type description: string
        :type enabled: bool
        :type user: enm_user.User object
        """
        super(EnmComRole, self).__init__(name, description, enabled, user)
        self.targets = targets if targets else {Target("ALL")}

    def create(self):
        self._create(additional_json={"type": "com"})

    def delete(self):
        self._delete()

    def update(self):
        self._update(additional_json={"type": "com"})


@persistable
class EnmRoleAlias(EnmRole):
    def __init__(self, name, roles, targets=None, description="", enabled=True, user=None):
        """
        :type name: string
        :type roles: set[EnmComRole]
        :type targets: set[Target]
        :type description: string
        :type enabled: bool
        :type user: enm_user_2.User
        """
        super(EnmRoleAlias, self).__init__(name, description, enabled, user)
        self.roles = roles
        self.targets = targets or {Target("ALL")}

    def create(self):
        existing_roles = self.get_all_roles()
        for role in self.roles:
            if role not in existing_roles:
                role.create()

        additional_json = {
            "type": "comalias",
            "assignRoles": [role.name for role in self.roles]
        }
        self._create(additional_json=additional_json)

    def delete(self):
        self._delete()


@persistable
class CustomRole(EnmRole):
    def __init__(self, name, roles=frozenset(), capabilities=frozenset(), description="", enabled=True, user=None,
                 policies=None, targets=None):
        """
        :type name: string
        :type roles: set[EnmComRole]
        :type capabilities: set[RoleCapability]
        :type description: string
        :type enabled: bool
        :type user : enm_user_2.User
        type policies: dict
        type targets: list[Target]
        """
        super(CustomRole, self).__init__(name, description, enabled, user, targets)
        self.capabilities = capabilities
        self.roles = roles
        self.policies = policies if policies is not None else {}

    def create(self):
        existing_roles = self.get_all_roles(self.user)
        for role in self.roles:
            if role not in existing_roles:
                role.create()

        capabilities_json = defaultdict(list)
        for capability in self.capabilities:
            capabilities_json[capability.resource].append(capability.operation)

        additional_json = {
            "type": "custom",
            "assignRoles": [role.name for role in self.roles],
            "policy": dict(capabilities_json),
        }
        self._create(additional_json=additional_json)

    def delete(self):
        self._delete()

    def update(self):
        """
        Updates a Custom ENM User Role

        :raises: HTTPError
        """
        existing_roles = self.get_all_roles(self.user)
        for role in self.roles:
            if role not in existing_roles:
                role.create()

        capabilities_json = defaultdict(list)
        for capability in self.capabilities:
            capabilities_json[capability.resource].append(capability.operation)

        additional_json = {
            "type": "custom",
            "assignRoles": [role.name for role in self.roles],
            "policy": dict(capabilities_json)
        }
        self._update(additional_json=additional_json)


@persistable
class RoleCapability(object):
    USECASES_URL = "/oss/idm/rolemanagement/usecases"

    def __init__(self, resource, operation, description="", user=None):
        self.resource = resource
        self.operation = operation
        self.description = description
        self.user = user or get_admin_user()

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.resource == other.resource and self.operation == other.operation

    def __str__(self):
        return "{}:{}".format(self.resource, self.operation)

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        return str(self)

    @classmethod
    def get_all_role_capabilities(cls, user=None):
        """
        :return: set[RoleCapability]
        """
        user = user or get_admin_user()
        response = user.get(cls.USECASES_URL, headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not get role capabilities: ")
        return set(RoleCapability(capability["resource"], capability["action"], capability["description"], user) for capability in response.json())

    @classmethod
    def get_role_capabilities_for_resource(cls, resource, user=None):
        """
        :type application_name: string
        :return: set[RoleCapability]
        """
        return set(role_capability for role_capability in cls.get_all_role_capabilities(user) if role_capability.resource == resource)


@persistable
class Target(object):

    BASE_URL = "/oss/idm/targetgroupmanagement/targetgroups"
    UPDATE_URL = BASE_URL + "/{target}/description"
    GET_ASSIGNMENT_URL = BASE_URL.replace('targetgroups', '') + "/targets?targetgroups={target}"
    UPDATE_ASSIGNMENT_URL = BASE_URL.replace('targetgroups', 'modifyassignment')
    DELETE_URL = BASE_URL + "/{target}"

    def __init__(self, name, description=""):
        """
        :type name: string
        :type description: string
        :type user: `enm_user_2.User`
        """
        self.name = name
        self.description = description

    @property
    def exists(self):
        for existing_target in self.get_existing_targets():
            if self.name == existing_target.name:
                return True

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        return str(self)

    @classmethod
    def get_existing_targets(cls, user=None):
        user = user or get_admin_user()

        response = user.get(cls.BASE_URL, headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not get ENM target groups: ")

        existing_targets = set()
        for target_info in response.json():
            existing_targets.add(Target(target_info["name"], target_info["description"]))

        return existing_targets

    def get_assigned_nodes(self):
        """
        Queries ENM to see if the target groups currently has node assignment

        :rtype: set
        :return: Set containing the nodes assigned to the target group
        """
        existing_nodes = set()

        response = self.user.get(self.GET_ASSIGNMENT_URL.format(target=self.name), headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not get ENM target group's assigned nodes: ")

        for node_dict in response.json():
            existing_nodes.add(node_dict.get("name"))

        return existing_nodes

    def create(self, create_as=None):
        """
        :raises HTTPRequestException: If an invalid response was returned
        """
        create_as = create_as or get_admin_user()

        body = {
            "name": self.name,
            "description": self.description
        }
        response = create_as.post(self.BASE_URL, json=body, headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not create target group: ")

    def update(self, description, user=None):
        """
        Update the Target Group description

        :type description: str
        :param description: Updated description of the Target Group
        :type user: `enm_user_2.User`
        :param user: ENM user who will perform the update

        raises: HTTPError

        :return: void
        """
        user = user or get_admin_user()
        body = {
            "description": description,
        }

        response = user.put(self.UPDATE_URL.format(target=self.name), json=body, headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not update target group: ")
        log.logger.debug("Successfully updated ENM Target Group {0}".format(self.name))

    def update_assignment(self, nodes, user=None):
        """
        Update the Target Group assignment

        :type nodes: `enm_node.Node`
        :param nodes: ENM nodes to assign to the Target Group

        raises: HTTPError,EnvironError

        :return: void
        """
        user = user or get_admin_user()
        if not nodes:
            raise EnvironError("Cannot update assignment without nodes.")
        body = []
        for node in set(nodes):
            body.append({"action": "ADD", "targetGroup": self.name, "target": node.node_id})
        response = user.put(self.UPDATE_ASSIGNMENT_URL, json=body, headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not update target group: ")
        log.logger.debug("Successfully updated ENM Target Group {0}".format(self.name))

    def delete(self, user=None):
        """
        Deletes a Target Group on ENM

        :type user: `enm_user_2.User`
        :param user: ENM user who will perform the deletion

        :raises: HTTPError
        """
        user = user or get_admin_user()
        response = user.delete_request(self.DELETE_URL.format(target=self.name), headers=SECURITY_REQUEST_HEADERS)
        raise_for_status(response, message_prefix="Could not delete target: ")
        log.logger.debug("Successfully deleted ENM target group {0}".format(self.name))

    def _teardown(self):
        """
        Secret teardown method
        """
        self.delete()


class Role(EnmRole):
    """
    Required to Maintain upgrade stability. Remove in 16.13
    """
    pass
