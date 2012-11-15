from requests.auth import AuthBase
import kerberos as k
import re
import logging

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

log = logging.getLogger(__name__)

def _negotiate_value(r):
    """Extracts the gssapi authentication token from the appropriate header"""

    authreq = r.headers.get('www-authenticate', None)

    if authreq:
        rx = re.compile('(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)
        mo = rx.search(authreq)
        if mo:
            return mo.group(1)

    return None

class HTTPKerberosAuth(AuthBase):
    """Attaches HTTP GSSAPI/Kerberos Authentication to the given Request object.
"""
    def __init__(self, require_mutual_auth=True):
        if k is None:
            raise Exception("Kerberos libraries unavailable")
        self.context = None
        self.require_mutual_auth = require_mutual_auth

    def generate_request_header(self, r):
        """Generates the gssapi authentication token with kerberos"""

        host = urlparse(r.url).netloc
        tail, _, head = host.rpartition(':')
        domain = tail if tail else head

        result, self.context = k.authGSSClientInit("HTTP@%s" % domain)

        if result < 1:
            raise Exception("authGSSClientInit failed")

        result = k.authGSSClientStep(self.context, _negotiate_value(r))

        if result < 0:
            raise Exception("authGSSClientStep failed")

        response = k.authGSSClientResponse(self.context)

        return "Negotiate %s" % response

    def authenticate_user(self, r):
        """Handles user authentication with gssapi/kerberos"""

        auth_header = self.generate_request_header(r)
        log.debug("authenticate_user(): Authorization header: %s" % auth_header)
        r.request.headers['Authorization'] = auth_header
        r.request.send(anyway=True)
        _r = r.request.response
        _r.history.append(r)
        log.debug("authenticate_user(): returning %s" % _r)
        return _r

    def handle_401(self, r):
        """Handles 401's, attempts to use gssapi/kerberos authentication"""

        log.debug("handle_401(): Handling: 401")
        if _negotiate_value(r) is not None:
            _r = self.authenticate_user(r)
            log.debug("handle_401(): returning %s" % _r)
            return _r
        else:
            log.debug("handle_401(): Kerberos is not supported")
            log.debug("handle_401(): returning %s" % r)
            return r

    def handle_other(self, r):
        """Handles all responses with the exception of 401s.

        This is necessary so that we can authenticate responses if requested"""

        log.debug("handle_other(): Handling: %d" % r.status_code)
        self.deregister(r)
        if self.require_mutual_auth:
            if _negotiate_value(r) is not None:
                log.debug("handle_other(): Authenticating the server")
                _r = self.authenticate_server(r)
                log.debug("handle_other(): returning %s" % _r)
                return _r
            else:
                log.error("handle_other(): Mutual authentication failed")
                raise Exception("Mutual authentication failed")
        else:
            log.debug("handle_other(): returning %s" % r)
            return r

    def authenticate_server(self, r):
        """Uses GSSAPI to authenticate the server"""

        log.debug("authenticate_server(): Authenticate header: %s" % _negotiate_value(r))
        result = k.authGSSClientStep(self.context, _negotiate_value(r))
        if  result < 1:
            raise Exception("authGSSClientStep failed")
        _r = r.request.response
        log.debug("authenticate_server(): returning %s" % _r)
        return _r

    def handle_response(self, r):
        """Takes the given response and tries kerberos-auth, as needed."""

        if r.status_code == 401:
            _r = self.handle_401(r)
            log.debug("handle_response returning %s" % _r)
            return _r
        else:
            _r = self.handle_other(r)
            log.debug("handle_response returning %s" % _r)
            return _r

        log.debug("handle_response returning %s" % r)
        return r

    def deregister(self, r):
        """Deregisters the response handler"""
        r.request.deregister_hook('response', self.handle_response)

    def __call__(self, r):
        r.register_hook('response', self.handle_response)
        return r
