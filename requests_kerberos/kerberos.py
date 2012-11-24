from requests.auth import AuthBase
from requests.compat import urlparse
import kerberos
import re
import logging

log = logging.getLogger(__name__)


def _negotiate_value(response):
    """Extracts the gssapi authentication token from the appropriate header"""
    if hasattr(_negotiate_value, 'regex'):
        regex = _negotiate_value.regex
    else:
        # There's no need to re-compile this EVERY time it is called. Compile
        # ile it once and you won't have the performance hit of the
        # compilation.
        regex = re.compile('(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)
        _negotiate_value.regex = regex

    authreq = response.headers.get('www-authenticate', None)

    if authreq:
        match_obj = regex.search(authreq)
        if match_obj:
            return match_obj.group(1)

    return None


class HTTPKerberosAuth(AuthBase):
    """Attaches HTTP GSSAPI/Kerberos Authentication to the given Request
    object."""
    def __init__(self, require_mutual_auth=True):
        self.context = None
        self.require_mutual_auth = require_mutual_auth

    def generate_request_header(self, response):
        """Generates the gssapi authentication token with kerberos"""
        host = urlparse(response.url).netloc
        tail, _, head = host.rpartition(':')
        domain = tail if tail else head

        result, self.context = kerberos.authGSSClientInit("HTTP@{0}".format(
            domain))

        if result < 1:
            raise Exception("authGSSClientInit failed")

        result = kerberos.authGSSClientStep(self.context,
                                            _negotiate_value(response))

        if result < 0:
            raise Exception("authGSSClientStep failed")

        gss_response = kerberos.authGSSClientResponse(self.context)

        return "Negotiate {0}".format(gss_response)

    def authenticate_user(self, response):
        """Handles user authentication with gssapi/kerberos"""

        auth_header = self.generate_request_header(response)
        log.debug("authenticate_user(): Authorization header: {0}".format(
            auth_header))
        response.request.headers['Authorization'] = auth_header
        response.request.send(anyway=True)
        _r = response.request.response
        _r.history.append(response)
        log.debug("authenticate_user(): returning {0}".format(_r))
        return _r

    def handle_401(self, response):
        """Handles 401's, attempts to use gssapi/kerberos authentication"""

        log.debug("handle_401(): Handling: 401")
        if _negotiate_value(response) is not None:
            _r = self.authenticate_user(response)
            log.debug("handle_401(): returning {0}".format(_r))
            return _r
        else:
            log.debug("handle_401(): Kerberos is not supported")
            log.debug("handle_401(): returning {0}".format(response))
            return response

    def handle_other(self, response):
        """Handles all responses with the exception of 401s.

        This is necessary so that we can authenticate responses if requested"""

        log.debug("handle_other(): Handling: %d" % response.status_code)
        self.deregister(response)
        if self.require_mutual_auth:
            if _negotiate_value(response) is not None:
                log.debug("handle_other(): Authenticating the server")
                _r = self.authenticate_server(response)
                log.debug("handle_other(): returning {0}".format(_r))
                return _r
            else:
                log.error("handle_other(): Mutual authentication failed")
                raise Exception("Mutual authentication failed")
        else:
            log.debug("handle_other(): returning {0}".format(response))
            return response

    def authenticate_server(self, response):
        """Uses GSSAPI to authenticate the server"""

        log.debug("authenticate_server(): Authenticate header: {0}".format(
                _negotiate_value(response)))  # nopep8
        result = kerberos.authGSSClientStep(self.context,
                                            _negotiate_value(response))
        if  result < 1:
            raise Exception("authGSSClientStep failed")
        _r = response.request.response
        log.debug("authenticate_server(): returning {0}".format(_r))
        return _r

    def handle_response(self, response):
        """Takes the given response and tries kerberos-auth, as needed."""

        if response.status_code == 401:
            _r = self.handle_401(response)
            log.debug("handle_response returning {0}".format(_r))
            return _r
        else:
            _r = self.handle_other(response)
            log.debug("handle_response returning {0}".format(_r))
            return _r

        log.debug("handle_response returning {0}".format(response))
        return response

    def deregister(self, response):
        """Deregisters the response handler"""
        response.request.deregister_hook('response', self.handle_response)

    def __call__(self, response):
        response.register_hook('response', self.handle_response)
        return response
