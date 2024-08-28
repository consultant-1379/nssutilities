import requests

import log
import mutexer
import timestamp

#
# TO BE EXECUTED WHEN THE MODULE LOADS - TO DISABLE SPURIOUS WARNINGS ABOUT UNVERIFIED CERTS
#
if hasattr(requests, "packages") and hasattr(requests.packages, "urllib3"):
    requests.packages.urllib3.disable_warnings()


class Response(object):

    """
    Wrapper class to wrap requests response object and create custom response attributes
    """

    def __init__(self, requests_response):
        """
        Constructs and sends a :class:`Response <Response>

        :param requests_response: The requests_response reference object
        :type requests_response: object

        :return: void

        """
        self._response = requests_response
        self.id = None

    @property
    def rc(self):
        return self._response.status_code

    @property
    def output(self):
        return self._response.text

    @property
    def headers(self):
        return self._response.headers

    @property
    def json(self):
        return self._response.json

    def __getattr__(self, name):
        return getattr(self._response, name)

    def log(self):
        """
        Logs the response headers, text, reason and duration

        :return: void

        """
        with mutexer.mutex("http-log-response"):
            log.logger.debug("RESPONSE - HTTP response (ID {0}):".format(self.id))
            log.logger.debug("         Status Code: {0}".format(self._response.status_code))

            if self._response.headers is not None:
                log.logger.debug(u"             Headers: {0}".format(self._response.headers))

            if self._response.text is not None and len(self._response.text) > 0:
                log.logger.debug(u"                Body: {0}".format(self._response.text))

            if self._response.status_code >= 300 and self._response.reason is not None:
                log.logger.debug(u"              Reason: {0}".format(self._response.reason))

            log.logger.debug(u"            Duration: {0}s".format(timestamp.get_string_elapsed_time(self._response.elapsed)))


class Request(object):
    id_counter = 1

    def __init__(self, method, url, params=None, data=None, headers=None,
                 cookies=None, files=None, auth=None, timeout=30, allow_redirects=True,
                 proxies=None, hooks=None, stream=None, verify=False, cert=None, json=None, verbose=True):
        """
        Constructs and sends a :class:`Request <Request>`

        :param: method: method for the new :class:`Request` object.
        :param: url: URL for the new :class:`Request` object.
        :param: params: (optional) Dictionary or bytes to be sent in the query string for the :class:`Request`.
        :param: data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param: json: (optional) json data to send in the body of the :class:`Request`.
        :param: headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
        :param: cookies: (optional) Dict or CookieJar object to send with the :class:`Request`.
        :param: files: (optional) Dictionary of ``'name': file-like-objects`` (or ``{'name': ('filename', fileobj)}``) for multipart encoding upload.
        :param: auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
        :param: timeout: (optional) How long to wait for the server to send data
            before giving up, as a float, or a (`connect timeout, read timeout
            <user/advanced.html#timeouts>`_) tuple.
        :type: timeout: float or tuple
        :param: allow_redirects: (optional) Boolean. Set to True if POST/PUT/DELETE redirect following is allowed.
        :type: allow_redirects: bool
        :param: proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
        :param: verify: (optional) if ``True``, the SSL cert will be verified. A CA_BUNDLE path can also be provided.
        :param: stream: (optional) if ``False``, the response content will be immediately downloaded.
        :param: cert: (optional) if String, path to ssl client cert file (.pem). If Tuple, ('cert', 'key') pair.
        :param: verbose: logs the request and response for debugging purposes, defaults to True

        :return: Response object
        :rtype: class

        """
        hooks = hooks or {}

        self.method = method
        self.url = url
        self.params = params
        self.data = data
        self.json = json
        self.headers = headers
        self.cookies = cookies
        self.files = files
        self.auth = auth
        self.timeout = timeout
        self.allow_redirects = allow_redirects
        self.proxies = proxies
        self.hooks = hooks
        self.stream = stream
        self.verify = verify
        self.cert = cert
        self.verbose = verbose
        self.response = None

        # Make sure that we have a unique ID that we can use to correlate each request and response
        with mutexer.mutex("assign-http-request-id"):
            self.id = Request.id_counter
            Request.id_counter = Request.id_counter + 1

    def execute(self):
        """
        Executes the http request

        :return: response
        :rtype: string

        """
        # Log the request details
        if self.verbose:
            self.log()

        # Make the request
        self.response = Response(
            requests.request(
                self.method, self.url, params=self.params, data=self.data, headers=self.headers,
                cookies=self.cookies, files=self.files, auth=self.auth, timeout=self.timeout,
                allow_redirects=self.allow_redirects, proxies=self.proxies, hooks=self.hooks,
                stream=self.stream, verify=self.verify, cert=self.cert, json=self.json))

        # Make sure that the same id gets set in the response so that we can map requests to responses
        self.response.id = self.id

        # Log the response details
        if self.verbose:
            self.response.log()

        return self.response

    def log(self):
        """
        Logs the http request headers, data, json and params

        :return: void

        """
        with mutexer.mutex("http-log-request"):
            log.logger.debug("REQUEST - Issuing HTTP {0} request (ID {1}) [timeout {2}s]:".format(self.method.upper(), self.id, self.timeout))
            log.logger.debug("                 URL: {0}".format(self.url))

            if self.headers is not None:
                log.logger.debug("             Headers: {0}".format(self.headers))

            if self.data is not None:
                log.logger.debug("                Data: {0}".format(self.data))

            if self.json is not None:
                log.logger.debug("         Data (JSON): {0}".format(self.json))

            if self.params is not None:
                log.logger.debug("              Params: {0}".format(self.params))

            log.logger.debug("     Allow redirects: {0}".format(self.allow_redirects))


def get(url, **kwargs):
    return Request('get', url, **kwargs).execute()


def post(url, **kwargs):
    return Request('post', url, **kwargs).execute()


def put(url, **kwargs):
    return Request('put', url, **kwargs).execute()


def delete(url, **kwargs):
    return Request('delete', url, **kwargs).execute()
