import requests
from nssutils.lib import cache, log, mutexer, http, config, filesystem, persistence, timestamp, arguments
from nssutils.lib.config import load_credentials_from_props
from nssutils.lib.enm_user_2 import _prompt_for_credentials, verify_credentials

DEFAULT_USER_DISPLAY_NAME = "default administrator"
ADMIN_SESSION_KEY = 'permanent-enm-admin-session'
USER_SESSION_KEY = "permanent-enm-sso-session-{0}"
SESSIONS_PER_USER = 5

#
# TO BE EXECUTED WHEN THE MODULE LOADS - TO DISABLE SPURIOUS WARNINGS ABOUT UNVERIFIED CERTS
#
if hasattr(requests, "packages") and hasattr(requests.packages, "urllib3"):
    requests.packages.urllib3.disable_warnings()


class UnauthorizedUserException(Exception):
    pass


# TO-DO username and password to be removed. This is temporary work-around for TORF-64797
def _get_sso_login_url():
    """
    B{Builds and returns the full ENM SSO login URL}

    @rtype: string
    """

    return "{0}/login".format(cache.get_apache_url())


def get_admin_credentials(allow_file_based_credentials=True):
    """
    B{Obtains the username and password of an ENM user account holding the SECURITY_ADMIN role and establishes an administrative session}

    @type allow_file_based_credentials: bool
    @param allow_file_based_credentials: Allow credentials to be loaded from file
    @rtype: void
    """

    # Flags whether we will store the password for this in persistence
    # We should only do this for internal tools or when password is in props
    keep_password = True
    credentials = None
    with mutexer.mutex("obtain-security-admin-credentials"):

        if filesystem.does_file_exist(config.get_prop('enm_admin_creds_file')):
            credentials = filesystem.get_lines_from_file(config.get_prop('enm_admin_creds_file'))
        else:
            if allow_file_based_credentials:
                # Check for props-based credentials
                credentials = load_credentials_from_props()

            # If we didn't find any file-based credentials, prompt for them
            if not credentials:
                keep_password = False
                credentials = _prompt_for_credentials("No stored password.", "username: ", "password: ")

    # Bail if we don't appear to have valid data
    if credentials is None or len(credentials) != 2:
        raise RuntimeError("Unable to obtain ENM SECURITY_ADMIN credentials")

    return credentials, keep_password


def establish_security_admin_session(allow_file_based_credentials=True):
    """
    B{Obtains the username and password of an ENM user account holding the SECURITY_ADMIN role and establishes an administrative session}

    @type allow_file_based_credentials: bool
    @param allow_file_based_credentials: Allow credentials to be loaded from file
    @rtype: void
    """

    if does_session_exist():
        return

    credentials, keep_password = get_admin_credentials(allow_file_based_credentials)

    # Establish the admin session
    establish_session(credentials[0], credentials[1], True, keep_password)


def does_session_exist(username=None):
    """
    B{Determines whether an ENM SSO session has been established for the specified user (or the security admin if the username is None)}

    @type username: string
    @param username: The username for this session

    @rtype: boolean
    """

    does_session_exist = False
    if username is not None:
        session_key = "permanent-enm-sso-session-{0}".format(username)
    else:
        session_key = "permanent-enm-admin-session"

    if persistence.has_key(session_key) and isinstance(persistence.get(session_key), Session):
        does_session_exist = persistence.get(session_key).is_session_valid()
    else:
        persistence.remove(session_key)

    return does_session_exist


def remove_session(username=None):
    """
    B{Removes an established ENM SSO session that has been established for the specified user (or the security admin if the username is None)}

    @type username: string
    @param username: The username for this session

    @rtype: void
    """
    if username is not None:
        session_key = USER_SESSION_KEY.format(username)
    else:
        session_key = ADMIN_SESSION_KEY

    persistence.remove(session_key)


def establish_session(username, password, is_admin=False, keep_password=False, force_new_session=False):
    """
    B{Establishes an ENM SSO session for the specified user; this function must be invoked before any requests can be serviced}

    @type username: string
    @param username: The username for this session
    @type password: string
    @param password: The password for this session
    @type is_admin: boolean
    @param is_admin: Indicates that the session being established is a security admin session
    @type keep_password: boolean
    @param keep_password: Indicates whether we store the password with the session or not
    @type force_new_session: boolean
    @param force_new_session: Indicates if we wish to establish new

    @rtype: void
    """

    if not force_new_session and does_session_exist(username if not is_admin else None):
        return

    if not verify_credentials(username, password):
        raise RuntimeError("Error. Invalid login credentials for user: {0}".format(username))

    session_key = ADMIN_SESSION_KEY if is_admin else USER_SESSION_KEY.format(username)

    session = Session(username, password, keep_password)

    # If we don't keep the password there is no point in keeping the session going for longer than 10 hours
    persistence.set(session_key, session, 129600 if keep_password else 35500)


def request(http_request, username=None, verbose=True, retry=False):
    """
    B{Issues a HTTP request using the established session for the specified user; if the username is None, the admin session is used}

    NOTE: This function requires a valid ENM session; establish_session() must be invoked before calling this function

    @type http_request: object <http.Request>
    @param http_request: The HTTP request to execute
    @type username: string
    @param username: The username for this session
    @type verbose: boolean
    @param verbose: Flag controlling whether additional information is printed to console during execution
    @rtype: object <requests.models.Response>

    @return: The response from the HTTP request
    """

    session = None
    session_key = USER_SESSION_KEY.format(username) if username else ADMIN_SESSION_KEY

    # If we have a valid session, grab it and update its expiration so that it's valid for another hour
    if persistence.has_key(session_key):
        session = persistence.get(session_key)

    # If the session is None or has expired and we don't have the password, no point in going on
    if session is None or not session.is_session_valid():
        user_name = session.username if session else username
        remove_session(username)
        raise RuntimeError("No valid, established ENM SSO session was found for user '{0}'".format(
            user_name if user_name else 'ADMINISTRATOR'))

    response = session.execute(http_request, verbose=verbose)

    if 'loginUsername' in response.output:
        log.logger.debug(
            "ERROR: Login page detected in response output therefore session lost on application side. Removing current session from persistence")
        if not retry:
            log.logger.debug("Attempting to re-establish the session and re-issue the request.")
            # Re-establish session
            _re_establish_session(session, False if username else True)

            # Retry request with new session
            return request(http_request, username, verbose, retry=True)
    elif response.rc == 403:
        remove_session(username)
        log.logger.debug("STATUS CODE 403: Response = {0}".format(response.output))
        raise UnauthorizedUserException(
            "ERROR: Return code of 403 returned: {} user may have insufficient access rights to make this request".format(
                username if username else "administrator"))
    else:
        # Re-persist the session with updated last_command_time attribute and updated timeout value if we have a password
        persistence.set(session_key, session, persistence.get_ttl(session_key) if not session.keep_password else 129600,
                        log_values=verbose)

    return response


def _re_establish_session(session=None, is_admin=True):
    """
    B{Attempts to re-establish a user session. It if is the administrator session it will remove it and re-establish the security admin session. If it's not an admin user session the administrator session is re-established and the user is deleted from ENM and re-added, automatically recreating the session}

    @type session: session.Session object
    @param session: The session.Session object to re-establish
    @type is_admin: boolean
    @param is_admin: If this is the administrator session or a user session to re-establish

    @rtype: void
    """
    from nssutils.lib.deprecated.enm_user import User
    remove_session()
    establish_security_admin_session()

    if not is_admin:
        password = session.password if session.password else arguments.get_random_string(15, password=True)
        user = User(session.username, password, roles=["ADMINISTRATOR"], suppress_output=True)
        remove_session(session.username)
        user.delete()
        if not user.create():
            raise RuntimeError("Unable to create user for cli_app tool")


class Session(object):
    def __init__(self, username, password, keep_password=False):
        """
        B{Session Constructor}

        @type username: string
        @param username: The username for this session
        @type password: string
        @param password: The password for this user
        @type keep_password: boolean
        @param keep_password: Indicates whether we store the password with the session or not
        """
        self.session = None
        self.username = username
        self.password = password
        self.keep_password = keep_password
        self.time_established = None
        self.last_command_time = None

    def _establish_cookies(self):
        """
        B{Initializes cookie for ENM SSO session}

        @rtype: boolean
        @return: True if the request was a success
        """

        result = False
        self.session = requests.Session()
        # Format the request payload and POST it
        payload = {"IDToken1": self.username, "IDToken2": self.password}
        r = self.session.post(_get_sso_login_url(), params=payload, verify=False, allow_redirects=False)

        if r.cookies is not None and "iPlanetDirectoryPro" in str(r.cookies):
            log.logger.debug("Successfully established ENM SSO session for user {0}".format(self.username))
            result = True
            self.time_established = timestamp.get_current_time()
        else:
            log.logger.debug("ERROR: Unexpected string in cookies '{0}'".format(str(r.cookies)))
            log.logger.debug("ERROR: Could not establish ENM SSO session for user {0}".format(self.username))

        if not self.keep_password:
            self.password = None

        return result

    def execute(self, http_request, verbose=True):
        """
        B{Issues a HTTP request via the session}

        @type http_request: object <http.Request>
        @param http_request: The HTTP request to execute
        @type verbose: boolean
        @param verbose: Flag controlling whether additional information is printed to console during execution

        @rtype: http.Response
        @return: The response from the HTTP request (<http.Response>)
        """

        # If the session is invalid or we haven't established a session yet, establish one
        if not any([self.time_established, self.last_command_time]) or not self.is_session_established():
            if self.password:
                with mutexer.mutex("establish-enm-sso-session-{0}".format(self.username)):
                    if not self._establish_cookies():
                        raise RuntimeError(
                            "Error in trying to establish session for user {0} with password {1}".format(self.username,
                                                                                                         self.password))
            else:
                raise RuntimeError(
                    "Previously established ENM SSO session for user '{0}' has expired".format(self.username))

        # Log the request before we execute it
        if verbose:
            with mutexer.mutex("session-mgr-log-request"):
                log.logger.debug("[{0}] Executing request ID {1}".format(self.username, http_request.id))
                http_request.log()

        # Merge the settings from the session with the http request
        request = self._merge_http_request(http_request)

        # Issue the request
        response = http.Response(self.session.send(request, verify=False))
        response.id = http_request.id
        self.last_command_time = timestamp.get_current_time()

        if verbose:
            response.log()

        return response

    def _merge_http_request(self, http_request):
        """
        B{Merges the settings from this session with the http request}

        @type http_request: object <http.Request>
        @param http_request: The HTTP request to execute

        @rtype: object <requests.PreparedRequest>
        @return: The prepared request with both settings merged from the session and the original HTTP request
        """

        return self.session.prepare_request(http_request)

    def is_session_established(self):
        """
        B{Checks to see if a session is expired or not}

        @rtype: boolean
        @return: Boolean which indicates whether a session has timed out yet
        """

        now = timestamp.get_current_time()
        return timestamp.get_elapsed_time_in_seconds(now - self.time_established) < 35500 and timestamp.get_elapsed_time_in_seconds(now - self.last_command_time) < 3500

    def is_session_valid(self):
        """
        B{Checks to see if the session is still valid or not}

        @rtype: boolean
        @return: Boolean which indicates whether a Session object is still useful
        """

        # If we have not issued a command yet the session has to be valid
        if self.keep_password or not self.time_established:
            is_valid = True
        else:
            is_valid = self.is_session_established()

        return is_valid
