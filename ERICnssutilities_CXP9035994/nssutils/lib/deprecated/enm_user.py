import json
import time
from nssutils.lib import config, http, log, cache, exception, headers
from nssutils.lib.enm_user_2 import verify_credentials, EnmRole
from urlparse import urljoin
import session_mgr

BASE_URL = '/oss/idm/usermanagement/users'
USER_URL = '/oss/idm/usermanagement/users/{username}/'
MODIFY_PRIVELEGES_URL = "/oss/idm/usermanagement/modifyprivileges"
QUERY_ALL_ROLES = "/oss/idm/rolemanagement/roles"
FORCE_PASSWORD_CHANGE_URL = urljoin(USER_URL, 'forcepasswordchange')
CHANGE_PASSWORD_URL = urljoin(USER_URL, 'password')


class User(object):

    def __init__(self, username, password, first_name=None, last_name=None, email=None, roles=(), establish_session=True, keep_password=False, verbose=False, suppress_output=False, password_reset_disabled=True, create_as=None):
        """
        B{Load user constructor}

        @type username: string
        @param username: The user's username
        @type password: string
        @param password: The user's password
        @type first_name: string
        @param first_name: The user's first name
        @type last_name: string
        @param last_name: The user's last name
        @type email: string
        @param email: The user's email
        @type roles: list[EnmRole] | list[str]
        @param roles: The openIDM security roles to which the user will be assigned
        @type establish_session: boolean
        @param establish_session: Establishes a session on ENM for the created username
        @type keep_password: boolean
        @param keep_password: Attaches password to a Session object for this ENM user so sessions can be re-established when they expire
        @type verbose: boolean
        @param verbose: Flag controlling whether additional information is printed to console during execution
        @type suppress_output: boolean
        @param suppress_output: Optional flag to toggle printing the command output to screen
        @type password_reset_disabled: boolean
        @param password_reset_disabled: Toggles whether or not to disable password reset after logging into ENM
        @rtype: object <enm_user.User>
        @return: A load user object
        """

        self.username = username
        self.password = password
        self.roles = [role if isinstance(role, EnmRole) else EnmRole(role) for role in roles]
        self.first_name = first_name
        self.last_name = last_name

        if self.first_name is None:
            self.first_name = username

        if self.last_name is None:
            self.last_name = username

        if email is None:
            self.email = "{0}@ericsson.com".format(self.username)
        else:
            self.email = email

        self.verbose = verbose
        self.suppress_output = suppress_output
        self.password_reset_disabled = password_reset_disabled

        self.user_type = "enmUser"
        self.status = "enabled"
        self.active = True
        self.nodes = []
        self.output = []
        self.establish_session = establish_session
        self.keep_password = keep_password
        # Defaults to None which means we will create the user as administrator
        self.create_as = create_as

        self.temp_password = 'TempPassw0rd'

    def _teardown(self):
        self.delete()

    def create(self):
        """
        B{Creates the user in ENM}

        @rtype: bool
        @return: True if the response returned a 200 OK
        """

        roles_assigned = False
        self.output = []

        # Remove unwanted characters from the list of roles so that we can print them nicely to the terminal
        roles_as_string = ", ".join(str(role) for role in self.roles)

        if self.verbose:
            self.output.append(log.cyan_text("Creating user {0} [{1}, {2}, {3}, ({4})]".format(self.username, self.first_name, self.last_name, log.purple_text(self.password), log.blue_text(roles_as_string))))

        log.logger.debug('Trying to create user "%s"' % self.username)
        http_request = self._build_create_user_http_request()
        response = session_mgr.request(http_request, verbose=False, username=self.create_as)
        try:
            # The try finally blocks are all here to protect a user from issuing multiple open-idm requests at the same time
            # When the ability to issue such requests is supported in the future, the try/finally blocks can be removed
            if response.ok:
                # Disable the security requirement to reset the user's password after logging in
                if self.password_reset_disabled:
                    self.change_password()

                roles_assigned = self.assign_to_roles(self.roles)
            else:
                self.output.append(log.red_text("Could not create user {0}".format(self.username)))
                self.output.append(log.red_text("  Output: {0}".format(self._error_message(response.output, "create"))))

            if response.ok and roles_assigned:
                log.logger.debug("Successfully created user {0} ({1})".format(self.username, roles_as_string))
                self.output.append(log.white_text("  Created user {0} [{1}, ({2})]".format(log.cyan_text(self.username), log.purple_text(self.password), log.purple_text(roles_as_string))))

                if self.establish_session:
                    # Bug where login invalid credentials exception raised if we don't sleep
                    established = False
                    for i in [6, 10, 9]:
                        try:
                            time.sleep(i)
                            session_mgr.establish_session(self.username, self.password, keep_password=self.keep_password)
                        except RuntimeError as e:
                            log.logger.debug('Cannot login with the user {0}, after sleeping for {1} seconds. Trying again... Error Message was {2}'.format(self.username, i, str(e)))
                        else:
                            established = True
                            break

                    if not established:
                        raise RuntimeError('Maximum retries reached. Cannot establish session for user %s' % self.username)

                else:
                    # If we disabled the password reset for a user we created, we only want to raise a runtime error if we cannot login with that credentials.
                    if self.password_reset_disabled and not verify_credentials(self.username, self.password):
                        raise RuntimeError("Unable to login with credentials username: {0} password: {1}".format(self.username, self.password))
            else:
                log.logger.debug("ERROR: Unable to create user {0} ({1})".format(self.username, roles_as_string))
                log.logger.debug("ERROR: Unable to assign role to user. Response output is: {0}".format(response.output))
                self.output.append(log.red_text("Unable to create user {0} with roles {1} ".format(self.username, roles_as_string)))
                raise RuntimeError("Could not assign role(s) {0} to user {1}".format(roles_as_string, self.username))

        except BaseException, err:
            log.logger.error("\nERROR: {0}".format(str(err)))
            self.delete()
            exception.process_exception()

        # Verbose mode contains a lot of output so lets separate the print output a little
        if self.verbose:
            self.output.append("")

        if not self.suppress_output:
            self._print_final_result_output()

        return roles_assigned

    def delete(self):
        """
        B{Deletes the user from ENM}

        @rtype: boolean
        @return: True if the response returned a 200 OK
        """

        result = False
        self.output = []

        if self.verbose:
            self.output.append(log.cyan_text("Deleting user {0}".format(log.cyan_text(self.username))))

        http_request = self._build_delete_user_http_request()
        response = session_mgr.request(http_request, verbose=False)

        if response.ok:
            result = True
            self.output.append(log.white_text("  Deleted user {0}".format(log.cyan_text(self.username))))
            log.logger.debug("Successfully deleted user {0}".format(self.username))
        else:
            log.logger.debug("Unable to delete user {0}".format(self.username))
            self.output.append(log.red_text("Unable to delete user {0}".format(self.username)))
            self.output.append(log.red_text("  Output: {0}".format(self._error_message(response.output, "delete"))))

        session_mgr.remove_session(self.username)
        # Verbose mode contains a lot of output so lets separate the print output a little
        if self.verbose:
            self.output.append("")

        if not self.suppress_output:
            self._print_final_result_output()

        return result

    def assign_to_roles(self, roles):
        """
        B{Assigns a user to one or many roles}

        @type roles: list[EnmRole]
        @param roles: List of openIDM roles in which to assign the user to
        @rtype: boolean
        @return: True if the response from each role update returned a 200 OK
        """

        result = False
        roles_as_string = ", ".join(str(role) for role in roles)
        if self.verbose:
            self.output.append(log.cyan_text("Assigning user {0} to roles {1}".format(self.username, log.purple_text(roles_as_string))))

        http_request = self._build_assign_user_to_roles_http_request(roles)
        response = session_mgr.request(http_request, verbose=False, username=self.create_as)

        if response.ok:
            result = True
            log.logger.debug("Successfully assigned roles {0} to user {1}".format(roles_as_string, self.username))
            log.logger.debug("    Output: {0}".format(response.output))
        else:
            log.logger.debug("Unable to assign roles {0} to user {1}".format(roles_as_string, self.username))
            log.logger.debug("    Output: {0}".format(response.output))
            self.output.append(log.red_text("Could not assign user {0} to roles {1}".format(self.username, roles_as_string)))
            self.output.append(log.red_text("  Output: {0}".format(self._error_message(response.output, "assign"))))

        return result

    def _build_assign_user_to_roles_http_request(self, roles):
        """
        B{Instantiates and returns a HTTP request object specific to this operation}

        @type roles: list[EnmRole]
        @param roles: List of openIDM roles in which to assign the user to
        @rtype: object <http.Request>
        @return: The HTTP request
        """
        payload = []
        apache_host_url = cache.get_apache_url()
        url = apache_host_url + MODIFY_PRIVELEGES_URL
        headers_dict = headers.SECURITY_REQUEST_HEADERS
        for role in roles:
            for target in role.targets:
                payload.append({"action": "ADD", "user": self.username, "targetGroup": target.name, "role": role.name})

        return http.Request("put", url, json=payload, headers=headers_dict)

    def _build_create_user_http_request(self):
        """
        B{Instantiates and returns a HTTP request object specific to this operation}

        Assigning user
        """

        apache_host_url = cache.get_apache_url()
        url = apache_host_url + BASE_URL
        headers_dict = headers.SECURITY_REQUEST_HEADERS
        password = self.temp_password if self.password_reset_disabled else self.password
        payload = {"username": self.username, "password": password, "status": self.status,
                   "name": self.first_name, "surname": self.last_name, "email": self.email}

        return http.Request("post", url, json=payload, headers=headers_dict)

    def _build_delete_user_http_request(self):
        """
        B{Instantiates and returns a HTTP request object specific to this operation}

        @rtype: object <http.Request>
        @return: The HTTP request
        """

        apache_host_url = cache.get_apache_url()
        url = apache_host_url + USER_URL.format(username=self.username)
        headers_dict = headers.SECURITY_REQUEST_HEADERS
        headers_dict.update({"If-Match": "*"})

        return http.Request("delete", url, headers=headers_dict)

    def build_get_user_request(self):
        """
        B{Instantiates and returns a HTTP request object specific to this operation}

        @rtype: object <http.Request>
        @return: The HTTP request to query all users
        """

        apache_host_url = cache.get_apache_url()
        url = config.get_prop("openidm_user_url").format(apache_hostname_url=apache_host_url, username=self.username)
        headers_dict = headers.SECURITY_REQUEST_HEADERS
        http_request = http.Request("get", url, headers=headers_dict)

        return http_request

    def _error_message(self, response_output, operation):
        """
        B{Returns a custom error message based on user operation}

        @type response_output: string
        @param response_output: A json string with output of the result of a user operation
        @type operation: string
        @param operation: A differentiator to decide which error message to return
        @rtype: string
        @return: The error message
        """
        error_msg = None

        # Covert the json response to a dict
        try:
            json_dict = json.loads(response_output)
        except:
            exception.process_exception()
            return "Malformed JSON response returned from user %s request" % operation

        # If there is an explanatory message in the json output print that to the user
        if "message" in json_dict:
            error_msg = json_dict["message"]
        else:
            if operation == "create":
                error_msg = "Either your username, password, or role does not match policy requirements"
            elif operation == "delete":
                error_msg = "Either the user was not created and cannot be deleted, or something went wrong during deletion"
            elif operation == "assign":
                error_msg = "Either the role was not assigned because it was invalid, or something went wrong during assignment"
            else:
                error_msg = "An error occured while trying to edit user(s)"

        return error_msg

    def _print_final_result_output(self):
        """
        B{Prints out each line of text that was appended to the user's output list}

        """
        for line in self.output:
            log.logger.info(line)

    def change_password(self):
        """
        B{Changes the password of user}

        @rtype: boolean
        @return: True if the response returned a 200 OK
        """

        log.logger.debug('Trying to change the password for user "%s"' % self.username)
        if self.verbose:
            self.output.append(log.cyan_text("Changing user password for '%s'" % self.username))

        http_request = self._build_change_password_request()
        response = session_mgr.request(http_request, verbose=False, username=self.create_as)

        if not response.ok:
            self.output.append(log.yellow_text("WARNING: Could not change the password for user '%s'" % self.username))

        return response.ok

    def _build_change_password_request(self):
        """
        B{Instantiates and returns a HTTP request object specific to this operation}

        @rtype: object <http.Request>
        @return: The HTTP request
        """

        apache_host_url = cache.get_apache_url()
        url = apache_host_url + CHANGE_PASSWORD_URL.format(username=self.username)
        json_ = {"oldPassword": self.temp_password, "password": self.password}
        headers_dict = headers.SECURITY_REQUEST_HEADERS
        return http.Request("put", url, json=json_, headers=headers_dict)
