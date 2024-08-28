#!/usr/bin/env python
import copy
import datetime
import os
import pkgutil
import re
import time
from functools import wraps
from random import uniform

import unipath
from enmscripting.private.session import ExternalSession
import mock
from mock import Mock, patch
from requests.cookies import RequestsCookieJar
from requests.models import Request, Response

from nssutils.lib import config, init, log, persistence, shell
from nssutils.lib.enm_node import NODE_CLASS_MAP
from nssutils.lib.enm_user_2 import ADMINISTRATOR_IDENTIFIER, EnmSession, User
from nssutils.tests import test_utils

NSSUTILS_PATH = unipath.Path(pkgutil.get_loader('nssutils').filename)

__config_dict = {}
__mock_config_file = os.path.join(NSSUTILS_PATH, 'etc', 'mock_values.conf')


def setup():
    """ Called from the setup of each unit test case """
    # To prevent each unit test from pulling in the config from all files (I/O load),
    # push a copy of the dict into the config module
    _push_config_dict()

    init.global_init("unit-test", "prod", "unit-test")

    # Keep a local copy of the config dict so that we can push it into config for future unit tests
    if len(__config_dict) == 0:
        build_config_dict(__mock_config_file)

    # Setup mocks
    _setup_mocks()
    test_utils.setup()

    # Monkey patch mutex_push as FakeRedis does not have an eval function. Therefore mutexes are not deleted and simply
    # expire after 30 seconds. Therefore we need to delete them instead
    def mutex_push_delete(self, mutex):
        self.connection.delete(mutex[0])
    persistence.Persistence.mutex_push = mutex_push_delete


def tear_down():
    test_utils.tear_down()
    persistence.clear_all()


def _push_config_dict():
    config.set_config_dict(__config_dict)


def build_config_dict(file=None):  # pylint: disable=redefined-builtin
    global __config_dict

    if file is not None:
        config.load_config_from_file(file)

    __config_dict = config.get_config_dict()


def _setup_mocks():
    # Mock logging
    log.logger.info = mock.Mock(return_value=None)
    log.logger.debug = mock.Mock(return_value=None)
    log.logger.warn = mock.Mock(return_value=None)
    log.logger.error = mock.Mock(return_value=None)
    log.logger.syslog = mock.Mock(return_value=None)
    log.logger.rest = mock.Mock(return_value=None)
    log.logger.exception = mock.Mock(return_value=None)
    log.logger.log_cmd = mock.Mock(return_value=None)
    log.logger.workload = mock.Mock(return_value=None)
    persistence.publish = mock.Mock(return_value=None)
    persistence.subscribe = mock.Mock(return_value=None)


def is_value_in_mocked_call_args(value, mocked_function, arg_position=None):
    """
    Checks if a value is present in any, or in a specific, argument call for the mocked function
    """

    result = False

    args, _ = mocked_function.call_args
    if arg_position is None:
        for arg in args:
            # Check if the arg is an int, as we cannot use the "in" operator on int types
            if isinstance(arg, int):
                if value == arg:
                    result = True
                    break
            elif value in arg:
                result = True
                break
    else:
        if value in args[arg_position]:
            result = True

    return result


class mock_datetime(object):

    def __init__(self, year, month, day, hour, minute):
        self.year = year
        self.month = month
        self.day = day
        self.hour = hour
        self.minute = minute
        self.original_datetime = None

    def __enter__(self):
        class MockDate(datetime.datetime):

            @classmethod
            def today(cls):
                return cls(self.year, self.month, self.day)

            @classmethod
            def now(cls):
                return cls(self.year, self.month, self.day,
                           self.hour, self.minute)
        self.original_datetime = datetime.datetime
        datetime.datetime = MockDate

    def __exit__(self, *args, **kwargs):
        datetime.datetime = self.original_datetime


def setup_test_node_objects(range_end=100, primary_type="ERBS", persist=False, node_version="16A", host_name="netsimlin537"):
    nodes = []
    range_end += 1

    for counter in range(1, range_end):
        if counter <= 9:
            name = "netsimlin537_{0}000{1}".format(primary_type, counter)
        elif counter <= 99:
            name = "netsimlin537_{0}00{1}".format(primary_type, counter)
        else:
            name = "netsimlin537_{0}0{1}".format(primary_type, counter)

        node_ip = "10.243.0.{0}".format(counter)
        mim_version = "4.1.189"
        netsim = host_name
        simulation = "LTE07"
        model_identity = "1094-174-285"
        node = NODE_CLASS_MAP[primary_type](
            name, node_ip, mim_version, model_identity, security_state='ON', normal_user='test',
            primary_type=primary_type, normal_password='test', secure_user='test', secure_password='test',
            subnetwork='subnetwork', netsim=netsim, simulation=simulation, user=mock_enm_user(),
            node_version=node_version)

        nodes.append(node)
        if persist:
            node._persist()
    return nodes


def get_mock(test_case, module_name, **kwargs):
    """
    Gets a mock for the specified module that persists until it is automatically cleaned up after tearDown() is called

    @type test_case: unittest2.TestCase
    @param test_case: Reference to the test case object that is running the tests
    @type module_name: str
    @param module_name: Name of the module to mock
    @rtype: MagicMock
    @returns: MagicMock setup with the return values or side effects, if specified
    """
    patcher = patch(module_name, **kwargs)
    _mock = patcher.start()
    test_case.addCleanup(patcher.stop)
    return _mock


def search_logs(pattern):
    """
    Checks if the specified message has been logged as INFO or WARN

    @type pattern: str
    @param pattern: The message pattern or substring that may appear in the logs
    @rtype: bool
    @return: True if the specified message appears as a substring in the INFO or WARN logs
    """
    log_list = [str(item[0][0]) for item in log.logger.info.call_args_list] + \
               [str(item[0][0]) for item in log.logger.warn.call_args_list] + \
               [str(item[0][0]) for item in log.logger.error.call_args_list] + \
               [str(item[0][0]) for item in log.logger.debug.call_args_list]

    return re.search(pattern, "\n".join(log_list))


class Responder(object):
    def __init__(self, responses):
        self.responses = responses
        self.call_count = dict.fromkeys(responses.keys(), 0)

    def __call__(self, *args, **kwargs):
        key = _convert_lists_to_tuple(args + tuple(kwargs.values()))
        return self._get_response(key)

    def _get_response(self, key):
        try:
            self.call_count[key] += 1
        except KeyError as e:
            raise IndexError("Called with unexpected arguments:\n\t" + str(e.args[0]))
        return self.responses[key]

    def verify_calls(self):
        uncalled_arguments = set(str(input_arguments) for input_arguments, call_count in self.call_count.iteritems() if not call_count)
        if uncalled_arguments:
            raise AssertionError("Function not called with arguments:\n\t{}".format("\n\t".join(uncalled_arguments)))

    def update_responses(self, additional_responses):
        self.call_count.update(dict.fromkeys(additional_responses.iterkeys(), 0))
        self.responses.update(additional_responses)


class UserRequestResponder(Responder):
    def __call__(self, endpoint, data=None, json=None, **kwargs):  # pylint: disable=arguments-differ
        return self._get_response(endpoint)


class HttpRequestResponder(Responder):
    def __call__(self, method, url, *args, **kwargs):
        key = (url.replace("https://apache.vts.com", ""), method)
        return self._get_response(key)


class TransientHttpRequestResponder(Responder):
    def __call__(self, method, url, **_):  # pylint: disable=arguments-differ
        key = (url.replace("https://apache.vts.com", ""), method)
        try:
            return self.responses[key].pop(0)
        except IndexError:
            raise IndexError("No more responses for the following output: {input}".format(input=key))
        except KeyError as e:
            raise IndexError("Called with unexpected arguments:\n\t" + str(e.args[0]))

    def verify_calls(self):
        uncalled_arguments = set("{call} (expected {count_left} more calls)".format(call=argument, count_left=len(calls_left)) for argument, calls_left in self.responses.iteritems() if len(calls_left))
        if uncalled_arguments:
            raise AssertionError("Function not called with arguments:\n\t{}".format("\n\t".join(uncalled_arguments)))


class RemoteCommandResponder(Responder):
    def __call__(self, command, *_):  # pylint: disable=arguments-differ
        return self._get_response(command.cmd)


def get_generic_responder_function(responses):
    """
    Creates and returns a responder function that returns value based on the input. This function uses the specified dictionary
    to determine what should be returned when it is called with specific arguments. This function should be used as a side_effect
    of a mock, as illustrated below.

    mock_set_cm_enabled.side_effect = self._get_generic_responder_function({
        (True): True
        (False): RuntimeError
    })

    @type responses: dict[tuple[any],any]
    @param responses: Mapping of inputs to outputs. The input must be a tuple that represents the list of arguments that the responder function may be called with
    @rtype: func
    @returns: A responder function that responds according to the specified input-output mapping
    @raises KeyError: If the responder function is called with arguments that is not listed in the specified dictionary
    """
    def responder(*args, **kwargs):
        """
        B{Function that returns an output based on an input using a dictionary (i.e. input-output mappings)
        @type args: any
        @param args: The input arguments to the function
        @type kwargs: any
        @param kwargs: The input keyword arguments to the function
        @rtype: any
        @return: The appropriate output that is mapped to the input
        """
        return responses[_convert_lists_to_tuple(args + tuple(kwargs.values()))]
    return responder


def _convert_lists_to_tuple(item):
    """
    Returns a tuple (i.e. hashable) representation of the argument if it is a list. Tuples with nested lists are also converted to tuples recursively

    @type item: any
    @param item: The item to convert to tuple if it is a list
    @rtype: any
    @return: A tuple if the argument is a list and nested tuples if there are lists nested
    """
    if isinstance(item, (list, tuple)):
        return tuple(_convert_lists_to_tuple(subitem) for subitem in item)
    elif isinstance(item, dict):
        return tuple(_convert_lists_to_tuple(subitem) for subitem in item.items())
    else:
        return item


def get_run_remote_cmd_responder_function(responses):
    """
    Creates and returns a responder function that returns value based on the input. This is an enhanced version of the
    get_generic_responder_function function, which has been modified to be used with the shell module's run_remote_cmd function.
    The responses are based on the command string and connection details, as illustrated below:

    mock_run_remote_cmd.side_effect = self.get_run_remote_cmd_responder_function({
        ("cmd", "hostname", "username", "password"): Mock(ok=True, stdout="result string")
    })

    @type responses: dict[tuple[any],any]
    @param responses: Mapping of inputs to outputs. The input must be a tuple that represents the list of arguments that the responder function may be called with
    @rtype: func
    @returns: A responder function that responds according to the specified input-output mapping
    @raises KeyError: If the responder function is called with arguments that is not listed in the specified dictionary
    """
    def responder(command_obj, hostname, username, password):
        """
        B{Function that returns an output based on an input using a dictionary (i.e. input-output mappings)

        @type command_obj: shell.Command
        @param command_obj: Command to be executed
        @type hostname: string
        @param hostname: IP address or hostname of the remote host on which the command is to be executed
        @type username: string
        @param username: Username of the account to use for the SSH connection
        @type password: string
        @param password: Password for the aforementioned user account (optional; not required for public key based connections)
        @rtype: any
        @return: The appropriate output that is mapped to the input
        """
        return responses[command_obj.cmd, hostname, username, password]
    return responder


def get_http_request_responder_function(endpoint_responses):
    """
    Creates and returns a responder function that returns value based on the input. This is an enhanced version of the
    get_generic_responder_function function, which has been modified to be used with session_mgr's HTTP request function. The responses are based
    on the REST endpoint and HTTP method, as illustrated below:

    mock_session_mgr_request.side_effect = unit_test_utils.get_http_request_responder_function({
        ("/pm-service/rest/subscription/", "GET"): Mock(rc=200, output=json.dumps({"id": 1,  "name": "cell_trace_subscription"})),
        ("/persistentObject/131568612", "POST"): Mock(rc=200, output=json.dumps({"moName": "sub1", "moType": "PMICScannerInfo"}))
    })

    @type endpoint_responses: dict[tuple[str,str],any]
    @param endpoint_responses: Mapping of inputs to outputs. The input must be a tuple that represents the REST endpoint and HTTP method that session_mgr.request may be called with
    @rtype: func
    @returns: A responder function that responds according to the specified input-output mapping
    @raises KeyError: If the responder function is called with a REST endpoint and HTTP method combination that is not listed in the specified dictionary
    """

    def responder(input_request, **_):
        """
        B{Function that returns an output based on an inputted HTTP request object using a dictionary (i.e. input-output mappings)
        @type input_request: object <http.Request>
        @param input_request: The HTTP request to mock a response for
        @rtype: any
        @return: The appropriate output that is mapped to the input REST URL and HTTP method
        """
        return endpoint_responses[input_request.url.replace("https://apache.vts.com", ""), input_request.method]
    return responder


def get_transient_http_request_responder_function(endpoint_responses):
    """
    Creates and returns a responder function that returns value based on the input. This is an enhanced version of the
    get_http_request_responder_function function, which has been modified return different responses based on the number
    of times the responder function is called.

    mock_session_mgr_request.side_effect = unit_test_utils.get_http_request_responder_function({
        ("/pm-service/rest/subscription/", "GET"): [
            Mock(rc=200, output=json.dumps({"id": 1,  "name": "cell_trace_subscription", "state": "UPDATING"}))
            Mock(rc=200, output=json.dumps({"id": 1,  "name": "cell_trace_subscription", "state": "UPDATED"}))
        ]
    })

    @type endpoint_responses: dict[tuple[str,str],list[any]]
    @param endpoint_responses: Mapping of inputs to outputs. The input must be a tuple that represents the REST endpoint and HTTP method that session_mgr.request may be called with
    @rtype: func
    @returns: A responder function that responds according to the specified input-output mapping
    @raises IndexError: If the responder function is called with a REST endpoint and HTTP method combination that is listed enough in the specified dictionary
    """

    def responder(input_request, **_):
        key = (input_request.url.replace("https://apache.vts.com", ""), input_request.method)
        try:
            return endpoint_responses[key].pop(0)
        except IndexError:
            raise IndexError("No more responses for the following output: {input}".format(input=key))
    return responder


def assert_file_content_equal(self, expected, actual):
    if os.path.isabs(expected):
        with open(expected) as expected_file_fd:
            expected_content = expected_file_fd.read()
    else:
        expected_content = expected

    if os.path.isabs(actual):
        with open(actual) as actual_file_fd:
            actual_content = actual_file_fd.read()
    else:
        actual_content = actual

    self.assertEqual(expected_content, actual_content)


def patch_netsim_executor(*func_paths):
    """
    Patches a call to the netsim executor allowing you to specify the rc, stderr and stdout you require from a request

    Example of use:
    # 1. Patch the test case that calls down to the netsim executor and add the extra arguments 'mock_connection_pool, *_'
    @patch_netsim_executor()
    def test_get_mo_types_on_nodes_returns_a_list_of_existing_mo_types(self, mock_connection_pool, *_):
        # 2 Call the setup function to setup required values on the test case
        unit_test_utils.setup_mock_shell_remote_connection(self)

        # 3 Add a response
        unit_test_utils.add_shell_connection_responses(self,
                stdout_response='>> dumpmotree:motypes="ManagedElement";\nManagedElement=1\n\nNumber of MOs: 1\n\n')

        # 4 setup the mock connection pool
        mock_pool = Mock()
        mock_pool.get_connection.return_value = self.mock_connection
        mock_connection_pool.return_value = mock_pool


    :param func_paths: the function to patch
    :return: patched function
    """

    def decorator(func):
        paths = list(copy.copy(func_paths))

        @wraps(func)
        def decorated(*args, **kwargs):
            return func(*args, **kwargs)
        paths = paths + ["nssutils.lib.shell.ConnectionPoolManager",
                         "nssutils.lib.netsim_executor.deploy_script",
                         "nssutils.lib.netsim_mgr.validate_netsim_connectivity"]
        for path in paths:
            decorated = patch(path)(decorated)
        return decorated
    return decorator


class SimulateNetworkActivityList(object):
    def __init__(self, values, max_delay=1):
        self.values = values
        self.max_delay = max_delay
        self.val = 0

    def append(self, values):
        self.values.append(values)

    def __iter__(self):
        return self

    def next(self):
        if self.val > len(self.values):
            raise StopIteration

        next_val = self.values[self.val]
        self.val += 1
        time.sleep(uniform(0.1, self.max_delay))
        return next_val


def setup_mock_shell_remote_connection(test_case):

    # Setup a place holder for the rc, stderr and stdout response for the connection
    test_case.rc_shell_responses = []
    test_case.stderr_responses = []
    test_case.stdout_responses = SimulateNetworkActivityList([])

    mock_stderr = Mock()
    mock_stderr.read.side_effect = test_case.stderr_responses

    mock_stdout = Mock()
    mock_stdout.read.side_effect = test_case.stdout_responses
    mock_stdout.channel.recv_exit_status.side_effect = test_case.rc_shell_responses

    test_case.mock_connection = Mock()
    test_case.mock_connection.exec_command.return_value = Mock(), mock_stdout, mock_stderr
    test_case.mock_connection.timed_out = False

    # make sure any previous connection managers have been torn down
    shell.delete_connection_mgr()


def add_shell_connection_responses(test_case, stdout_response, stderr_response='', return_code=0):
    test_case.stderr_responses.append(stderr_response)
    test_case.stdout_responses.append(stdout_response)
    test_case.rc_shell_responses.append(return_code)


def mock_enm_user(username=None, session_url='http://localhost', persist=False):
    user = User(username if username else "TestUser", "T3stP4ssw0rd")
    session = ExternalSession()
    session.cookies = RequestsCookieJar()
    session.cookies.set('iPlanetDirectoryPro', 'test')
    session._url = session_url
    user.enm_session = EnmSession(session)
    if persist:
        persistence.set(user.username, user, -1)
    return user


def mock_admin_session():
    user = mock_enm_user(username=ADMINISTRATOR_IDENTIFIER)
    persistence.set(User._PERSISTENCE_KEY.format(username=ADMINISTRATOR_IDENTIFIER), user, -1)
    return user


def get_http_response(method, url, status_code, text):
    response = Response()
    response.status_code = status_code
    response.request = Request()
    response.request.method = method
    response.request.url = url
    response._content = text
    return response
