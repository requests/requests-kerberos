"""
requests Kerberos/GSSAPI authentication library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Requests is an HTTP library, written in Python, for human beings. This library
adds optional Kerberos/SPNEGO (GSSAPI - Linux/SSPI - Windows) authentication support and supports mutual
authentication. Basic GET usage:

    >>> import requests
    >>> from requests_kerberos import HTTPKerberosAuth
    >>> r = requests.get("http://example.org", auth=HTTPKerberosAuth())

    >>> import requests
    >>> from requests_kerberos import HTTPSpnegoAuth
    >>> r = requests.get("http://example.org", auth=HTTPSpnegoAuth())

The entire `requests.api` should be supported.
"""
import logging

from .kerberos_ import HTTPKerberosAuth, HTTPSpnegoAuth, REQUIRED, OPTIONAL, DISABLED
from .exceptions import MutualAuthenticationError
from .compat import NullHandler

logging.getLogger(__name__).addHandler(NullHandler())

__all__ = ('HTTPKerberosAuth', 'HTTPSpnegoAuth', 'MutualAuthenticationError', 'REQUIRED',
           'OPTIONAL', 'DISABLED')
__version__ = '0.12.0'
