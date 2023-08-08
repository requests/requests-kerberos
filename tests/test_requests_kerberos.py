#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for requests_kerberos."""

import base64
import warnings

import pytest
import requests
import requests_kerberos
import requests_kerberos.kerberos_ as kerb
import spnego
import spnego.exceptions

from urllib.parse import urlparse


@pytest.fixture(scope="function")
def mock_client(mocker, monkeypatch):
    mock_client = mocker.MagicMock()
    mock_client.return_value.step.return_value = b"GSSRESPONSE"
    monkeypatch.setattr(spnego, "client", mock_client)

    # Not used in the tests and disables warnings about a non-urllib3 backend which is fired due to the use of mocks
    monkeypatch.setattr(kerb, "_get_channel_bindings_application_data", mocker.MagicMock(return_value=None))

    yield mock_client


def test_negotate_value_extraction():
    response = requests.Response()
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    assert requests_kerberos.kerberos_._negotiate_value(response) == b"token"


def test_negotate_value_extraction_none():
    response = requests.Response()
    response.headers = {}
    assert requests_kerberos.kerberos_._negotiate_value(response) is None


def test_force_preemptive(mock_client):
    auth = requests_kerberos.HTTPKerberosAuth(force_preemptive=True)

    request = requests.Request(url="http://www.example.org")

    auth.__call__(request)

    assert 'Authorization' in request.headers
    assert request.headers.get('Authorization') == 'Negotiate R1NTUkVTUE9OU0U='


def test_no_force_preemptive():
    auth = requests_kerberos.HTTPKerberosAuth()

    request = requests.Request(url="http://www.example.org")

    auth.__call__(request)

    assert 'Authorization' not in request.headers


def test_generate_request_header(mock_client):
    response = requests.Response()
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    host = urlparse(response.url).hostname
    auth = requests_kerberos.HTTPKerberosAuth()

    assert auth.generate_request_header(response, host) == "Negotiate R1NTUkVTUE9OU0U="
    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"token",
    }


def test_generate_request_header_init_error(mock_client):
    response = requests.Response()
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    host = urlparse(response.url).hostname
    auth = requests_kerberos.HTTPKerberosAuth()

    mock_client.side_effect = spnego.exceptions.BadNameError()
    with pytest.raises(requests_kerberos.exceptions.KerberosExchangeError, match="ctx init failed"):
        auth.generate_request_header(response, host)

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }

    assert mock_client.return_value.step.call_count == 0


def test_generate_request_header_step_error(mock_client):
    response = requests.Response()
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    host = urlparse(response.url).hostname
    auth = requests_kerberos.HTTPKerberosAuth()

    mock_client.return_value.step.side_effect = spnego.exceptions.InvalidTokenError()
    with pytest.raises(requests_kerberos.exceptions.KerberosExchangeError, match="ctx step failed"):
        auth.generate_request_header(response, host)

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"token",
    }


def test_authenticate_user(mock_client, mocker):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {'www-authenticate': 'negotiate c2VydmVydG9rZW4='}

    connection = mocker.MagicMock()
    connection.send.return_value = response_ok

    request = requests.Request()
    response = requests.Response()
    response.request = request
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    response.status_code = 401
    response.connection = connection
    response._content = ""
    response.raw = mocker.MagicMock(return_value=None)
    auth = requests_kerberos.HTTPKerberosAuth()
    r = auth.authenticate_user(response)

    assert response in r.history
    assert r == response_ok
    assert request.headers["Authorization"] == "Negotiate R1NTUkVTUE9OU0U="

    assert connection.send.call_count == 1
    assert connection.send.call_args[0] == (request,)
    assert response.raw.release_conn.call_count == 1
    assert response.raw.release_conn.call_args[0] == ()

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"token",
    }


def test_authenticate_user2(mock_client, mocker):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {'proxy-authenticate': 'negotiate c2VydmVydG9rZW4='}

    connection = mocker.MagicMock()
    connection.send.return_value = response_ok

    request = requests.Request()
    response = requests.Response()
    response.request = request
    response.url = "http://www.example.org/"
    response.headers = {'proxy-authenticate': 'negotiate dG9rZW4='}
    response.status_code = 407
    response.connection = connection
    response._content = ""
    response.raw = mocker.MagicMock(return_value=None)
    auth = requests_kerberos.HTTPKerberosAuth()
    kwa = {'proxies' : {'http': 'http://www.example.org:10080', 'https': 'https://www.example.org:10080'} }
    r = auth.authenticate_user(response, **kwa)

    assert response in r.history
    assert r == response_ok
    assert request.headers["Proxy-Authorization"] == "Negotiate R1NTUkVTUE9OU0U="

    assert connection.send.call_count == 1
    assert connection.send.call_args[0] == (request,)
    assert connection.send.call_args[1] == kwa
    assert response.raw.release_conn.call_count == 1
    assert response.raw.release_conn.call_args[0] == ()

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"token",
    }

def test_handle_401(mock_client, mocker):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {'www-authenticate': 'negotiate c2VydmVydG9rZW4='}

    connection = mocker.MagicMock()
    connection.send.return_value = response_ok

    request = requests.Request()
    response = requests.Response()
    response.request = request
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    response.status_code = 401
    response.connection = connection
    response._content = ""
    response.raw = mocker.MagicMock(return_value=None)
    auth = requests_kerberos.HTTPKerberosAuth()
    r = auth.handle_401(response)

    assert response in r.history
    assert r == response_ok
    assert request.headers["Authorization"] == "Negotiate R1NTUkVTUE9OU0U="

    assert connection.send.call_count == 1
    assert connection.send.call_args[0] == (request,)
    assert response.raw.release_conn.call_count == 1
    assert response.raw.release_conn.call_args[0] == ()

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"token",
    }


def test_handle_407(mock_client, mocker):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {'proxy-authenticate': 'negotiate c2VydmVydG9rZW4='}

    connection = mocker.MagicMock()
    connection.send.return_value = response_ok

    request = requests.Request()
    response = requests.Response()
    response.request = request
    response.url = "http://www.example.org/"
    response.headers = {'proxy-authenticate': 'negotiate dG9rZW4='}
    response.status_code = 407
    response.connection = connection
    response._content = ""
    response.raw = mocker.MagicMock(return_value=None)
    auth = requests_kerberos.HTTPKerberosAuth()
    kwa = {'proxies' : {'http': 'http://www.example.org:10080', 'https': 'https://www.example.org:10080'} }
    r = auth.handle_407(response, **kwa)

    assert response in r.history
    assert r == response_ok
    assert request.headers["Proxy-Authorization"] == "Negotiate R1NTUkVTUE9OU0U="

    assert connection.send.call_count == 1
    assert connection.send.call_args[0] == (request,)
    assert connection.send.call_args[1] == kwa
    assert response.raw.release_conn.call_count == 1
    assert response.raw.release_conn.call_args[0] == ()

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"token",
    }


def test_authenticate_server(mock_client):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {
        'www-authenticate': 'negotiate c2VydmVydG9rZW4=',
        'authorization': 'Negotiate R1NTUkVTUE9OU0U='}

    auth = requests_kerberos.HTTPKerberosAuth()
    auth._context = {"www.example.org": mock_client.return_value}
    result = auth.authenticate_server(response_ok)

    assert result is True
    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"servertoken",
    }


def test_handle_other(mock_client):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {
        'www-authenticate': 'negotiate c2VydmVydG9rZW4=',
        'authorization': 'Negotiate R1NTUkVTUE9OU0U='}

    auth = requests_kerberos.HTTPKerberosAuth()
    auth._context = {"www.example.org": mock_client.return_value}

    r = auth.handle_other(response_ok)
    assert r == response_ok
    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"servertoken",
    }


def test_handle_response_200(mock_client):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {
        'www-authenticate': 'negotiate c2VydmVydG9rZW4=',
        'authorization': 'Negotiate R1NTUkVTUE9OU0U='}

    auth = requests_kerberos.HTTPKerberosAuth()
    auth._context = {"www.example.org": mock_client.return_value}

    r = auth.handle_response(response_ok)
    assert r == response_ok
    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"servertoken",
    }


def test_handle_response_200_mutual_auth_required_failure(mock_client):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {}

    auth = requests_kerberos.HTTPKerberosAuth()
    auth._context = {"www.example.org": mock_client.return_value}

    with pytest.raises(requests_kerberos.MutualAuthenticationError):
        auth.handle_response(response_ok)

    assert mock_client.return_value.step.call_count == 0


def test_handle_response_200_mutual_auth_required_failure_2(mock_client):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {
        'www-authenticate': 'negotiate c2VydmVydG9rZW4=',
        'authorization': 'Negotiate R1NTUkVTUE9OU0U='}

    auth = requests_kerberos.HTTPKerberosAuth()
    auth._context = {"www.example.org": mock_client.return_value}

    mock_client.return_value.step.side_effect = spnego.exceptions.InvalidCredentialError()
    with pytest.raises(requests_kerberos.MutualAuthenticationError, match="Unable to authenticate"):
        auth.handle_response(response_ok)

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"servertoken",
    }


def test_handle_response_200_mutual_auth_optional_hard_failure(mock_client):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {
        'www-authenticate': 'negotiate c2VydmVydG9rZW4=',
        'authorization': 'Negotiate R1NTUkVTUE9OU0U='}

    auth = requests_kerberos.HTTPKerberosAuth(
        requests_kerberos.OPTIONAL)
    auth._context = {"www.example.org": mock_client.return_value}

    mock_client.return_value.step.side_effect = spnego.exceptions.InvalidTokenError()
    with pytest.raises(requests_kerberos.MutualAuthenticationError, match="Unable to authenticate"):
        auth.handle_response(response_ok)

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"servertoken",
    }


def test_handle_response_200_mutual_auth_optional_soft_failure(mock_client):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200

    auth = requests_kerberos.HTTPKerberosAuth(
        requests_kerberos.OPTIONAL)
    auth._context = {"www.example.org": mock_client.return_value}

    r = auth.handle_response(response_ok)

    assert r == response_ok
    assert mock_client.return_value.step.call_count == 0


def test_handle_response_500_mutual_auth_required_failure(mock_client):
    response_500 = requests.Response()
    response_500.url = "http://www.example.org/"
    response_500.status_code = 500
    response_500.headers = {}
    response_500.request = "REQUEST"
    response_500.connection = "CONNECTION"
    response_500._content = "CONTENT"
    response_500.encoding = "ENCODING"
    response_500.raw = "RAW"
    response_500.cookies = "COOKIES"

    auth = requests_kerberos.HTTPKerberosAuth()
    auth._context = {"www.example.org": mock_client.return_value}

    r = auth.handle_response(response_500)

    assert isinstance(r, requests_kerberos.kerberos_.SanitizedResponse)
    assert r != response_500
    assert r.headers != response_500.headers
    assert r.status_code == response_500.status_code
    assert r.encoding == response_500.encoding
    assert r.raw == response_500.raw
    assert r.url == response_500.url
    assert r.reason == response_500.reason
    assert r.connection == response_500.connection
    assert r.content == ''
    assert r.cookies != response_500.cookies

    assert mock_client.return_value.step.call_count == 0

    # re-test with error response sanitizing disabled
    auth = requests_kerberos.HTTPKerberosAuth(sanitize_mutual_error_response=False)
    auth._context = {"www.example.org": mock_client.return_value}

    r = auth.handle_response(response_500)

    assert not isinstance(r, requests_kerberos.kerberos_.SanitizedResponse)


def test_handle_response_500_mutual_auth_optional_failure(mock_client):
    response_500 = requests.Response()
    response_500.url = "http://www.example.org/"
    response_500.status_code = 500
    response_500.headers = {}
    response_500.request = "REQUEST"
    response_500.connection = "CONNECTION"
    response_500._content = "CONTENT"
    response_500.encoding = "ENCODING"
    response_500.raw = "RAW"
    response_500.cookies = "COOKIES"

    auth = requests_kerberos.HTTPKerberosAuth(
        requests_kerberos.OPTIONAL)
    auth._context = {"www.example.org": mock_client.return_value}

    r = auth.handle_response(response_500)

    assert r == response_500

    assert mock_client.return_value.step.call_count == 0


def test_handle_response_401(mock_client, mocker):
    # Get a 401 from server, authenticate, and get a 200 back.
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {'www-authenticate': 'negotiate c2VydmVydG9rZW4='}


    connection = mocker.MagicMock()
    connection.send.return_value = response_ok

    request = requests.Request()
    response = requests.Response()
    response.request = request
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    response.status_code = 401
    response.connection = connection
    response._content = ""
    response.raw = mocker.MagicMock(return_value=None)
    auth = requests_kerberos.HTTPKerberosAuth()
    auth.handle_other = mocker.MagicMock(return_value=response_ok)

    r = auth.handle_response(response)

    assert response in r.history
    assert auth.handle_other.call_count == 1
    assert auth.handle_other.call_args[0] == (response_ok,)
    assert r == response_ok
    assert request.headers["Authorization"] == "Negotiate R1NTUkVTUE9OU0U="

    assert connection.send.call_count == 1
    assert connection.send.call_args[0] == (request,)

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"token",
    }


def test_handle_response_401_rejected(mock_client, mocker):
    # Get a 401 from server, authenticate, and get another 401 back.
    # Ensure there is no infinite recursion.
    connection = mocker.MagicMock()

    def connection_send(self, *args, **kwargs):
        reject = requests.Response()
        reject.url = "http://www.example.org/"
        reject.status_code = 401
        reject.connection = connection
        return reject

    connection.send.side_effect = connection_send

    request = requests.Request()
    response = requests.Response()
    response.request = request
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    response.status_code = 401
    response.connection = connection
    response._content = ""
    response.raw = mocker.MagicMock(return_value=None)

    auth = requests_kerberos.HTTPKerberosAuth()

    r = auth.handle_response(response)

    assert r.status_code == 401
    assert request.headers["Authorization"] == "Negotiate R1NTUkVTUE9OU0U="

    assert connection.send.call_count == 1
    assert connection.send.call_args[0] == (request,)
    assert response.raw.release_conn.call_count == 1
    assert response.raw.release_conn.call_args[0] == ()


    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"token",
    }


def test_generate_request_header_custom_service(mock_client):
    response = requests.Response()
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    host = urlparse(response.url).hostname
    auth = requests_kerberos.HTTPKerberosAuth(service="barfoo")
    auth.generate_request_header(response, host),

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "barfoo",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }


def test_delegation(mock_client, mocker):
    response_ok = requests.Response()
    response_ok.url = "http://www.example.org/"
    response_ok.status_code = 200
    response_ok.headers = {'www-authenticate': 'negotiate c2VydmVydG9rZW4='}

    connection = mocker.MagicMock()
    connection.send.return_value = response_ok

    request = requests.Request()
    response = requests.Response()
    response.request = request
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    response.status_code = 401
    response.connection = connection
    response._content = ""
    response.raw = mocker.MagicMock(return_value=None)
    auth = requests_kerberos.HTTPKerberosAuth(1, "HTTP", True)
    r = auth.authenticate_user(response)

    assert response in r.history
    assert r == response_ok
    assert request.headers["Authorization"] == "Negotiate R1NTUkVTUE9OU0U="

    assert connection.send.call_count == 1
    assert connection.send.call_args[0] == (request,)

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth | spnego.ContextReq.delegate,
        "protocol": "kerberos",
    }

    assert mock_client.return_value.step.call_count == 1
    assert mock_client.return_value.step.call_args[1] == {
        "in_token": b"token",
    }


def test_principal_override(mock_client):
    response = requests.Response()
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    host = urlparse(response.url).hostname
    auth = requests_kerberos.HTTPKerberosAuth(principal="user@REALM")
    auth.generate_request_header(response, host),

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": "user@REALM",
        "password": None,
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }

def test_principal_override_with_pass(mock_client):
    response = requests.Response()
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    host = urlparse(response.url).hostname
    auth = requests_kerberos.HTTPKerberosAuth(principal="user@REALM",password="password")
    auth.generate_request_header(response, host),

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": "user@REALM",
        "password": "password",
        "hostname": "www.example.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }


def test_realm_override(mock_client):
    response = requests.Response()
    response.url = "http://www.example.org/"
    response.headers = {'www-authenticate': 'negotiate dG9rZW4='}
    host = urlparse(response.url).hostname
    auth = requests_kerberos.HTTPKerberosAuth(hostname_override="otherhost.otherdomain.org")
    auth.generate_request_header(response, host),

    assert mock_client.call_count == 1
    assert mock_client.call_args[1] == {
        "username": None,
        "password": None,
        "hostname": "otherhost.otherdomain.org",
        "service": "HTTP",
        "channel_bindings": None,
        "context_req": spnego.ContextReq.sequence_detect | spnego.ContextReq.mutual_auth,
        "protocol": "kerberos",
    }


def test_cbt_rsa_md5():
    cert_der = b'MIIDGzCCAgOgAwIBAgIQJzshhViMG5hLHIJHxa+TcTANBgkqhkiG9w0' \
                b'BAQQFADAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MD' \
                b'MxNloXDTE4MDUzMDA4MjMxNlowFTETMBEGA1UEAwwKU0VSVkVSMjAxN' \
                b'jCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN9N5GAzI7uq' \
                b'AVlI6vUqhY5+EZWCWWGRwR3FT2DEXE5++AiJxXO0i0ZfAkLu7UggtBe' \
                b'QwVNkaPD27EYzVUhy1iDo37BrFcLNpfjsjj8wVjaSmQmqvLvrvEh/BT' \
                b'C5SBgDrk2+hiMh9PrpJoB3QAMDinz5aW0rEXMKitPBBiADrczyYrliF' \
                b'AlEU6pTlKEKDUAeP7dKOBlDbCYvBxKnR3ddVH74I5T2SmNBq5gzkbKP' \
                b'nlCXdHLZSh74USu93rKDZQF8YzdTO5dcBreJDJsntyj1o49w9WCt6M7' \
                b'+pg6vKvE+tRbpCm7kXq5B9PDi42Nb6//MzNaMYf9V7v5MHapvVSv3+y' \
                b'sCAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGA' \
                b'QUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0G' \
                b'A1UdDgQWBBTh4L2Clr9ber6yfY3JFS3wiECL4DANBgkqhkiG9w0BAQQ' \
                b'FAAOCAQEA0JK/SL7SP9/nvqWp52vnsxVefTFehThle5DLzagmms/9gu' \
                b'oSE2I9XkQIttFMprPosaIZWt7WP42uGcZmoZOzU8kFFYJMfg9Ovyca+' \
                b'gnG28jDUMF1E74KrC7uynJiQJ4vPy8ne7F3XJ592LsNJmK577l42gAW' \
                b'u08p3TvEJFNHy2dBk/IwZp0HIPr9+JcPf7v0uL6lK930xHJHP56XLzN' \
                b'YG8vCMpJFR7wVZp3rXkJQUy3GxyHPJPjS8S43I9j+PoyioWIMEotq2+' \
                b'q0IpXU/KeNFkdGV6VPCmzhykijExOMwO6doUzIUM8orv9jYLHXYC+i6' \
                b'IFKSb6runxF1MAik+GCSA=='

    expected_hash = b'\x23\x34\xB8\x47\x6C\xBF\x4E\x6D\xFC\x76\x6A\x5D' \
                    b'\x5A\x30\xD6\x64\x9C\x01\xBA\xE1\x66\x2A\x5C\x3A' \
                    b'\x13\x02\xA9\x68\xD7\xC6\xB0\xF6'
    actual_hash = kerb._get_certificate_hash(base64.b64decode(cert_der))
    assert actual_hash == expected_hash


def test_cbt_rsa_sha1():
    cert_der = b'MIIDGzCCAgOgAwIBAgIQJg/Mf5sR55xApJRK+kabbTANBgkqhkiG9w0' \
                b'BAQUFADAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MD' \
                b'MxNloXDTE4MDUzMDA4MjMxNlowFTETMBEGA1UEAwwKU0VSVkVSMjAxN' \
                b'jCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALPKwYikjbzL' \
                b'Lo6JtS6cyytdMMjSrggDoTnRUKauC5/izoYJd+2YVR5YqnluBJZpoFp' \
                b'hkCgFFohUOU7qUsI1SkuGnjI8RmWTrrDsSy62BrfX+AXkoPlXo6IpHz' \
                b'HaEPxjHJdUACpn8QVWTPmdAhwTwQkeUutrm3EOVnKPX4bafNYeAyj7/' \
                b'AGEplgibuXT4/ehbzGKOkRN3ds/pZuf0xc4Q2+gtXn20tQIUt7t6iwh' \
                b'nEWjIgopFL/hX/r5q5MpF6stc1XgIwJjEzqMp76w/HUQVqaYneU4qSG' \
                b'f90ANK/TQ3aDbUNtMC/ULtIfHqHIW4POuBYXaWBsqalJL2VL3YYkKTU' \
                b'sCAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGA' \
                b'QUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0G' \
                b'A1UdDgQWBBS1jgojcjPu9vqeP1uSKuiIonGwAjANBgkqhkiG9w0BAQU' \
                b'FAAOCAQEAKjHL6k5Dv/Zb7dvbYEZyx0wVhjHkCTpT3xstI3+TjfAFsu' \
                b'3zMmyFqFqzmr4pWZ/rHc3ObD4pEa24kP9hfB8nmr8oHMLebGmvkzh5h' \
                b'0GYc4dIH7Ky1yfQN51hi7/X5iN7jnnBoCJTTlgeBVYDOEBXhfXi3cLT' \
                b'u3d7nz2heyNq07gFP8iN7MfqdPZndVDYY82imLgsgar9w5d+fvnYM+k' \
                b'XWItNNCUH18M26Obp4Es/Qogo/E70uqkMHost2D+tww/7woXi36X3w/' \
                b'D2yBDyrJMJKZLmDgfpNIeCimncTOzi2IhzqJiOY/4XPsVN/Xqv0/dzG' \
                b'TDdI11kPLq4EiwxvPanCg=='

    expected_hash = b'\x14\xCF\xE8\xE4\xB3\x32\xB2\x0A\x34\x3F\xC8\x40' \
                    b'\xB1\x8F\x9F\x6F\x78\x92\x6A\xFE\x7E\xC3\xE7\xB8' \
                    b'\xE2\x89\x69\x61\x9B\x1E\x8F\x3E'
    actual_hash = kerb._get_certificate_hash(base64.b64decode(cert_der))
    assert actual_hash == expected_hash


def test_cbt_rsa_sha256():
    cert_der = b'MIIDGzCCAgOgAwIBAgIQWkeAtqoFg6pNWF7xC4YXhTANBgkqhkiG9w0' \
                b'BAQsFADAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUyNzA5MD' \
                b'I0NFoXDTE4MDUyNzA5MjI0NFowFTETMBEGA1UEAwwKU0VSVkVSMjAxN' \
                b'jCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIPKM5uykFy' \
                b'NmVoLyvPSXGk15ZDqjYi3AbUxVFwCkVImqhefLATit3PkTUYFtAT+TC' \
                b'AwK2E4lOu1XHM+Tmp2KIOnq2oUR8qMEvfxYThEf1MHxkctFljFssZ9N' \
                b'vASDD4lzw8r0Bhl+E5PhR22Eu1Wago5bvIldojkwG+WBxPQv3ZR546L' \
                b'MUZNaBXC0RhuGj5w83lbVz75qM98wvv1ekfZYAP7lrVyHxqCTPDomEU' \
                b'I45tQQZHCZl5nRx1fPCyyYfcfqvFlLWD4Q3PZAbnw6mi0MiWJbGYKME' \
                b'1XGicjqyn/zM9XKA1t/JzChS2bxf6rsyA9I7ibdRHUxsm1JgKry2jfW' \
                b'0CAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGA' \
                b'QUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0G' \
                b'A1UdDgQWBBQabLGWg1sn7AXPwYPyfE0ER921ZDANBgkqhkiG9w0BAQs' \
                b'FAAOCAQEAnRohyl6ZmOsTWCtxOJx5A8yr//NweXKwWWmFQXRmCb4bMC' \
                b'xhD4zqLDf5P6RotGV0I/SHvqz+pAtJuwmr+iyAF6WTzo3164LCfnQEu' \
                b'psfrrfMkf3txgDwQkA0oPAw3HEwOnR+tzprw3Yg9x6UoZEhi4XqP9AX' \
                b'R49jU92KrNXJcPlz5MbkzNo5t9nr2f8q39b5HBjaiBJxzdM1hxqsbfD' \
                b'KirTYbkUgPlVOo/NDmopPPb8IX8ubj/XETZG2jixD0zahgcZ1vdr/iZ' \
                b'+50WSXKN2TAKBO2fwoK+2/zIWrGRxJTARfQdF+fGKuj+AERIFNh88HW' \
                b'xSDYjHQAaFMcfdUpa9GGQ=='

    expected_hash = b'\x99\x6F\x3E\xEA\x81\x2C\x18\x70\xE3\x05\x49\xFF' \
                    b'\x9B\x86\xCD\x87\xA8\x90\xB6\xD8\xDF\xDF\x4A\x81' \
                    b'\xBE\xF9\x67\x59\x70\xDA\xDB\x26'
    actual_hash = kerb._get_certificate_hash(base64.b64decode(cert_der))
    assert actual_hash == expected_hash


def test_cbt_rsa_sha384():
    cert_der = b'MIIDGzCCAgOgAwIBAgIQEmj1prSSQYRL2zYBEjsm5jANBgkqhkiG9w0' \
                b'BAQwFADAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MD' \
                b'MxN1oXDTE4MDUzMDA4MjMxN1owFTETMBEGA1UEAwwKU0VSVkVSMjAxN' \
                b'jCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKsK5NvHi4xO' \
                b'081fRLMmPqKsKaHvXgPRykLA0SmKxpGJHfTAZzxojHVeVwOm87IvQj2' \
                b'JUh/yrRwSi5Oqrvqx29l2IC/qQt2xkAQsO51/EWkMQ5OSJsl1MN3NXW' \
                b'eRTKVoUuJzBs8XLmeraxQcBPyyLhq+WpMl/Q4ZDn1FrUEZfxV0POXgU' \
                b'dI3ApuQNRtJOb6iteBIoQyMlnof0RswBUnkiWCA/+/nzR0j33j47IfL' \
                b'nkmU4RtqkBlO13f6+e1GZ4lEcQVI2yZq4Zgu5VVGAFU2lQZ3aEVMTu9' \
                b'8HEqD6heyNp2on5G/K/DCrGWYCBiASjnX3wiSz0BYv8f3HhCgIyVKhJ' \
                b'8CAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGA' \
                b'QUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0G' \
                b'A1UdDgQWBBQS/SI61S2UE8xwSgHxbkCTpZXo4TANBgkqhkiG9w0BAQw' \
                b'FAAOCAQEAMVV/WMXd9w4jtDfSrIsKaWKGtHtiMPpAJibXmSakBRwLOn' \
                b'5ZGXL2bWI/Ac2J2Y7bSzs1im2ifwmEqwzzqnpVKShIkZmtij0LS0SEr' \
                b'6Fw5IrK8tD6SH+lMMXUTvp4/lLQlgRCwOWxry/YhQSnuprx8IfSPvil' \
                b'kwZ0Ysim4Aa+X5ojlhHpWB53edX+lFrmR1YWValBnQ5DvnDyFyLR6II' \
                b'Ialp4vmkzI9e3/eOgSArksizAhpXpC9dxQBiHXdhredN0X+1BVzbgzV' \
                b'hQBEwgnAIPa+B68oDILaV0V8hvxrP6jFM4IrKoGS1cq0B+Ns0zkG7ZA' \
                b'2Q0W+3nVwSxIr6bd6hw7g=='

    expected_hash = b'\x34\xF3\x03\xC9\x95\x28\x6F\x4B\x21\x4A\x9B\xA6' \
                    b'\x43\x5B\x69\xB5\x1E\xCF\x37\x58\xEA\xBC\x2A\x14' \
                    b'\xD7\xA4\x3F\xD2\x37\xDC\x2B\x1A\x1A\xD9\x11\x1C' \
                    b'\x5C\x96\x5E\x10\x75\x07\xCB\x41\x98\xC0\x9F\xEC'
    actual_hash = kerb._get_certificate_hash(base64.b64decode(cert_der))
    assert actual_hash == expected_hash


def test_cbt_rsa_sha512():
    cert_der = b'MIIDGzCCAgOgAwIBAgIQUDHcKGevZohJV+TkIIYC1DANBgkqhkiG9w0' \
                b'BAQ0FADAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MD' \
                b'MxN1oXDTE4MDUzMDA4MjMxN1owFTETMBEGA1UEAwwKU0VSVkVSMjAxN' \
                b'jCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKr9bo/XXvHt' \
                b'D6Qnhb1wyLg9lDQxxe/enH49LQihtVTZMwGf2010h81QrRUe/bkHTvw' \
                b'K22s2lqj3fUpGxtEbYFWLAHxv6IFnIKd+Zi1zaCPGfas9ekqCSj3vZQ' \
                b'j7lCJVGUGuuqnSDvsed6g2Pz/g6mJUa+TzjxN+8wU5oj5YVUK+aing1' \
                b'zPSA2MDCfx3+YzjxVwNoGixOz6Yx9ijT4pUsAYQAf1o9R+6W1/IpGgu' \
                b'oax714QILT9heqIowwlHzlUZc1UAYs0/JA4CbDZaw9hlJyzMqe/aE46' \
                b'efqPDOpO3vCpOSRcSyzh02WijPvEEaPejQRWg8RX93othZ615MT7dqp' \
                b'ECAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGA' \
                b'QUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0G' \
                b'A1UdDgQWBBTgod3R6vejt6kOASAApA19xIG6kTANBgkqhkiG9w0BAQ0' \
                b'FAAOCAQEAVfz0okK2bh3OQE8cWNbJ5PjJRSAJEqVUvYaTlS0Nqkyuaj' \
                b'gicP3hb/pF8FvaVaB6r7LqgBxyW5NNL1xwdNLt60M2zaULL6Fhm1vzM' \
                b'sSMc2ynkyN4++ODwii674YcQAnkUh+ZGIx+CTdZBWJfVM9dZb7QjgBT' \
                b'nVukeFwN2EOOBSpiQSBpcoeJEEAq9csDVRhEfcB8Wtz7TTItgOVsilY' \
                b'dQY56ON5XszjCki6UA3GwdQbBEHjWF2WERqXWrojrSSNOYDvxM5mrEx' \
                b'sG1npzUTsaIr9w8ty1beh/2aToCMREvpiPFOXnVV/ovHMU1lFQTNeQ0' \
                b'OI7elR0nJ0peai30eMpQQ=='

    expected_hash = b'\x55\x6E\x1C\x17\x84\xE3\xB9\x57\x37\x0B\x7F\x54' \
                    b'\x4F\x62\xC5\x33\xCB\x2C\xA5\xC1\xDA\xE0\x70\x6F' \
                    b'\xAE\xF0\x05\x44\xE1\xAD\x2B\x76\xFF\x25\xCF\xBE' \
                    b'\x69\xB1\xC4\xE6\x30\xC3\xBB\x02\x07\xDF\x11\x31' \
                    b'\x4C\x67\x38\xBC\xAE\xD7\xE0\x71\xD7\xBF\xBF\x2C' \
                    b'\x9D\xFA\xB8\x5D'
    actual_hash = kerb._get_certificate_hash(base64.b64decode(cert_der))
    assert actual_hash == expected_hash


def test_cbt_ecdsa_sha1():
    cert_der = b'MIIBjjCCATSgAwIBAgIQRCJw7nbtvJ5F8wikRmwgizAJBgcqhkjOPQQ' \
                b'BMBUxEzARBgNVBAMMClNFUlZFUjIwMTYwHhcNMTcwNTMwMDgwMzE3Wh' \
                b'cNMTgwNTMwMDgyMzE3WjAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MFkwE' \
                b'wYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk3fOh178kRglmnPKe9K/mbgi' \
                b'gf8YgNq62rF2EpfzpyQY0eGw4xnmKDG73aZ+ATSlV2IybxiUVsKyMUn' \
                b'LhPfvmaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQ' \
                b'UFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggpTRVJWRVIyMDE2MB0GA' \
                b'1UdDgQWBBQSK8qwmiQmyAWWya3FxQDj9wqQAzAJBgcqhkjOPQQBA0kA' \
                b'MEYCIQCiOsP56Iqo+cHRvCp2toj65Mgxo/PQY1tn+S3WH4RJFQIhAJe' \
                b'gGQuaPWg6aCWV+2+6pNCNMdg/Nix+mMOJ88qCBNHi'

    expected_hash = b'\x1E\xC9\xAD\x46\xDE\xE9\x34\x0E\x45\x03\xCF\xFD' \
                    b'\xB5\xCD\x81\x0C\xB2\x6B\x77\x8F\x46\xBE\x95\xD5' \
                    b'\xEA\xF9\x99\xDC\xB1\xC4\x5E\xDA'
    actual_hash = kerb._get_certificate_hash(base64.b64decode(cert_der))
    assert actual_hash == expected_hash


def test_cbt_ecdsa_sha256():
    cert_der = b'MIIBjzCCATWgAwIBAgIQeNQTxkMgq4BF9tKogIGXUTAKBggqhkjOPQQ' \
                b'DAjAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MDMxN1' \
                b'oXDTE4MDUzMDA4MjMxN1owFTETMBEGA1UEAwwKU0VSVkVSMjAxNjBZM' \
                b'BMGByqGSM49AgEGCCqGSM49AwEHA0IABDAfXTLOaC3ElgErlgk2tBlM' \
                b'wf9XmGlGBw4vBtMJap1hAqbsdxFm6rhK3QU8PFFpv8Z/AtRG7ba3UwQ' \
                b'prkssClejZzBlMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBg' \
                b'EFBQcDAgYIKwYBBQUHAwEwFQYDVR0RBA4wDIIKU0VSVkVSMjAxNjAdB' \
                b'gNVHQ4EFgQUnFDE8824TYAiBeX4fghEEg33UgYwCgYIKoZIzj0EAwID' \
                b'SAAwRQIhAK3rXA4/0i6nm/U7bi6y618Ci2Is8++M3tYIXnEsA7zSAiA' \
                b'w2s6bJoI+D7Xaey0Hp0gkks9z55y976keIEI+n3qkzw=='

    expected_hash = b'\xFE\xCF\x1B\x25\x85\x44\x99\x90\xD9\xE3\xB2\xC9' \
                    b'\x2D\x3F\x59\x7E\xC8\x35\x4E\x12\x4E\xDA\x75\x1D' \
                    b'\x94\x83\x7C\x2C\x89\xA2\xC1\x55'
    actual_hash = kerb._get_certificate_hash(base64.b64decode(cert_der))
    assert actual_hash == expected_hash


def test_cbt_ecdsa_sha384():
    cert_der = b'MIIBjzCCATWgAwIBAgIQcO3/jALdQ6BOAoaoseLSCjAKBggqhkjOPQQ' \
                b'DAzAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA4MDMxOF' \
                b'oXDTE4MDUzMDA4MjMxOFowFTETMBEGA1UEAwwKU0VSVkVSMjAxNjBZM' \
                b'BMGByqGSM49AgEGCCqGSM49AwEHA0IABJLjZH274heB/8PhmhWWCIVQ' \
                b'Wle1hBZEN3Tk2yWSKaz9pz1bjwb9t79lVpQE9tvGL0zP9AqJYHcVOO9' \
                b'YG9trqfejZzBlMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBg' \
                b'EFBQcDAgYIKwYBBQUHAwEwFQYDVR0RBA4wDIIKU0VSVkVSMjAxNjAdB' \
                b'gNVHQ4EFgQUkRajoFr8qZ/8L8rKB3zGiGolDygwCgYIKoZIzj0EAwMD' \
                b'SAAwRQIgfi8dAxXljCMSvngtDtagGCTGBs7Xxh8Z3WX6ZwJZsHYCIQC' \
                b'D4iNReh1afXKYC0ipjXWAIkiihnEEycCIQMbkMNst7A=='

    expected_hash = b'\xD2\x98\x7A\xD8\xF2\x0E\x83\x16\xA8\x31\x26\x1B' \
                    b'\x74\xEF\x7B\x3E\x55\x15\x5D\x09\x22\xE0\x7F\xFE' \
                    b'\x54\x62\x08\x06\x98\x2B\x68\xA7\x3A\x5E\x3C\x47' \
                    b'\x8B\xAA\x5E\x77\x14\x13\x5C\xB2\x6D\x98\x07\x49'
    actual_hash = kerb._get_certificate_hash(base64.b64decode(cert_der))
    assert actual_hash == expected_hash


def test_cbt_ecdsa_sha512():
    cert_der = b'MIIBjjCCATWgAwIBAgIQHVj2AGEwd6pOOSbcf0skQDAKBggqhkjOPQQ' \
                b'DBDAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA3NTUzOV' \
                b'oXDTE4MDUzMDA4MTUzOVowFTETMBEGA1UEAwwKU0VSVkVSMjAxNjBZM' \
                b'BMGByqGSM49AgEGCCqGSM49AwEHA0IABL8d9S++MFpfzeH8B3vG/PjA' \
                b'AWg8tGJVgsMw9nR+OfC9ltbTUwhB+yPk3JPcfW/bqsyeUgq4//LhaSp' \
                b'lOWFNaNqjZzBlMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBg' \
                b'EFBQcDAgYIKwYBBQUHAwEwFQYDVR0RBA4wDIIKU0VSVkVSMjAxNjAdB' \
                b'gNVHQ4EFgQUKUkCgLlxoeai0EtQrZth1/BSc5kwCgYIKoZIzj0EAwQD' \
                b'RwAwRAIgRrV7CLpDG7KueyFA3ZDced9dPOcv2Eydx/hgrfxYEcYCIBQ' \
                b'D35JvzmqU05kSFV5eTvkhkaDObd7V55vokhm31+Li'

    expected_hash = b'\xE5\xCB\x68\xB2\xF8\x43\xD6\x3B\xF4\x0B\xCB\x20' \
                    b'\x07\x60\x8F\x81\x97\x61\x83\x92\x78\x3F\x23\x30' \
                    b'\xE5\xEF\x19\xA5\xBD\x8F\x0B\x2F\xAA\xC8\x61\x85' \
                    b'\x5F\xBB\x63\xA2\x21\xCC\x46\xFC\x1E\x22\x6A\x07' \
                    b'\x24\x11\xAF\x17\x5D\xDE\x47\x92\x81\xE0\x06\x87' \
                    b'\x8B\x34\x80\x59'
    actual_hash = kerb._get_certificate_hash(base64.b64decode(cert_der))
    assert actual_hash == expected_hash


def test_cbt_invalid_signature_algorithm():
    # Manually edited from test_ecdsa_sha512 to change the OID to '1.2.840.10045.4.3.5'
    cert_der = b'MIIBjjCCATWgAwIBAgIQHVj2AGEwd6pOOSbcf0skQDAKBggqhkjOPQQ' \
                b'DBTAVMRMwEQYDVQQDDApTRVJWRVIyMDE2MB4XDTE3MDUzMDA3NTUzOV' \
                b'oXDTE4MDUzMDA4MTUzOVowFTETMBEGA1UEAwwKU0VSVkVSMjAxNjBZM' \
                b'BMGByqGSM49AgEGCCqGSM49AwEHA0IABL8d9S++MFpfzeH8B3vG/PjA' \
                b'AWg8tGJVgsMw9nR+OfC9ltbTUwhB+yPk3JPcfW/bqsyeUgq4//LhaSp' \
                b'lOWFNaNqjZzBlMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBg' \
                b'EFBQcDAgYIKwYBBQUHAwEwFQYDVR0RBA4wDIIKU0VSVkVSMjAxNjAdB' \
                b'gNVHQ4EFgQUKUkCgLlxoeai0EtQrZth1/BSc5kwCgYIKoZIzj0EAwUD' \
                b'RwAwRAIgRrV7CLpDG7KueyFA3ZDced9dPOcv2Eydx/hgrfxYEcYCIBQ' \
                b'D35JvzmqU05kSFV5eTvkhkaDObd7V55vokhm31+Li'

    expected_hash = None
    expected_warning = "Failed to get signature algorithm from " \
                        "certificate, unable to pass channel bindings:"

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        actual_hash = kerb._get_certificate_hash(base64.b64decode(cert_der))
        assert actual_hash == expected_hash
        assert expected_warning in str(w[-1].message)
