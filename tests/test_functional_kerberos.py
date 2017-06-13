import requests
import os
import unittest

from requests_kerberos import HTTPKerberosAuth, REQUIRED


class KerberosFunctionalTestCase(unittest.TestCase):

    def setUp(self):
        """Setup."""
        self.principal = os.environ.get('KERBEROS_PRINCIPAL', None)
        self.url = os.environ.get('KERBEROS_URL', None)

        # Skip the test if not set
        if self.principal is None:
            raise unittest.SkipTest("KERBEROS_PRINCIPAL is not set, skipping functional tests")
        if self.url is None:
            raise unittest.SkipTest("KERBEROS_URL is not set, skipping functional tests")

    def test_successful_http_call(self):
        session = requests.Session()
        session.auth = HTTPKerberosAuth(mutual_authentication=REQUIRED, principal=self.principal)
        request = requests.Request('GET', self.url)
        prepared_request = session.prepare_request(request)

        response = session.send(prepared_request)

        assert response.status_code == 200, "HTTP response with kerberos auth did not return a 200 error code"
        assert False

if __name__ == '__main__':
    unittest.main()
