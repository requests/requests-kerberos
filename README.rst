requests Kerberos/GSSAPI authentication library
===============================================

Requests is an HTTP library, written in Python, for human beings. This library
adds optional Kerberos/GSSAPI authentication support and supports mutual
authentication. Basic GET usage:


.. code-block:: pycon

    >>> import requests
    >>> from requests_kerberos import HTTPKerberosAuth
    >>> r = requests.get("http://example.org", auth=HTTPKerberosAuth())
    ...

The entire ``requests.api`` should be supported.

Mutual Authentication
---------------------

By default, ``HTTPKerberosAuth`` will require mutual authentication from the
server, and if a server emits a non-error response which is cannot be
authenticated, a ``requests_kerberos.errors.MutualAuthenticationError`` will be
raised. IF a server emits an error which cannot be authenticated, it will be
returned to the user but with it's contents and headers stripped.

OPTIONAL
^^^^^^^^

If you'd prefer to not require mutual authentication, you can set your
preference when constructing your ``HTTPKerberosAuth`` object:

.. code-block:: pycon

    >>> import requests
    >>> from requests_kerberos import HTTPKerberosAuth, OPTIONAL
    >>> kerberos_auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
    >>> r = requests.get("http://example.org", auth=kerberos_auth)
    ...

This will cause ``requests_kerberos`` to attempt mutual authentication if the
server advertises that it supports it, and cause a failure if authentication
fails, but not if the server does not support it at all.

DISABLED
^^^^^^^^

While we don't recommend it, if you'd prefer to never attempt mutual
authentication, you can do that as well:

.. code-block:: pycon

    >>> import requests
    >>> from requests_kerberos import HTTPKerberosAuth, DISABLED
    >>> kerberos_auth = HTTPKerberosAuth(mutual_authentication=DISABLED)
    >>> r = requests.get("http://example.org", auth=kerberos_auth)
    ...
