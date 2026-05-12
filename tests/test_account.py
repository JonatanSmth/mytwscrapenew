import pytest

import httpx

from twscrape.account import Account, ClientCookieInjectionError, CookieInjectionFailure, XSession
from twscrape.xclid import ClientStateViolationError


class DummyClient:
    def __init__(self):
        self.cookies = httpx.Cookies()
        self.headers = {}


def test_make_client_sets_browser_cookies_and_csrf():
    account = Account(
        username="user",
        password="pass",
        email="user@example.com",
        email_password="email_pass",
        user_agent="test-agent",
        active=True,
        locks={},
        stats={},
        headers={},
        cookies={"auth_token": "token", "ct0": "csrf", "twid": "twid"},
        mfa_code=None,
        proxy=None,
        error_msg=None,
        last_used=None,
        _tx=None,
    )

    client = account.make_client()

    assert client.cookies["auth_token"] == "token"
    assert client.cookies["ct0"] == "csrf"
    assert client.cookies["twid"] == "twid"
    assert client.headers["x-csrf-token"] == "csrf"
    assert client.headers["user-agent"] == "test-agent"


def test_xsession_injects_dict_cookies_into_httpx_jar():
    client = DummyClient()
    XSession(
        cookies={"auth_token": "token", "ct0": "csrf"},
        headers={},
    ).apply_to_client(client)

    assert len(client.cookies.jar) == 2
    assert {c.name for c in client.cookies.jar} == {"auth_token", "ct0"}


def test_xsession_injects_list_cookie_structure_into_httpx_jar():
    client = DummyClient()
    XSession(
        cookies=[
            {"name": "auth_token", "value": "token"},
            {"name": "ct0", "value": "csrf"},
        ],
        headers={},
    ).apply_to_client(client)

    assert len(client.cookies.jar) == 2
    assert {c.name for c in client.cookies.jar} == {"auth_token", "ct0"}


def test_xsession_fallback_set_injection_when_update_empty():
    client = DummyClient()
    client.cookies.update = lambda *args, **kwargs: None

    XSession(
        cookies={"auth_token": "token", "ct0": "csrf"},
        headers={},
    ).apply_to_client(client)

    assert len(client.cookies.jar) == 2
    assert {c.name for c in client.cookies.jar} == {"auth_token", "ct0"}


def test_xsession_raises_cookie_injection_failure_when_jar_remains_empty_after_fallback():
    client = DummyClient()
    client.cookies.update = lambda *args, **kwargs: None
    client.cookies.set = lambda *args, **kwargs: None

    with pytest.raises(CookieInjectionFailure):
        XSession(
            cookies={"auth_token": "token", "ct0": "csrf"},
            headers={},
        ).apply_to_client(client)


def test_make_client_raises_when_cookie_injection_fails():
    account = Account(
        username="user",
        password="pass",
        email="user@example.com",
        email_password="email_pass",
        user_agent="test-agent",
        active=True,
        locks={},
        stats={},
        headers={},
        cookies={"auth_token": "token", "ct0": "csrf", "twid": "twid"},
        mfa_code=None,
        proxy=None,
        error_msg=None,
        last_used=None,
        _tx=None,
    )

    # Simulate empty client cookie jar by replacing apply_to_client with a no-op
    original_apply = XSession.apply_to_client
    try:
        XSession.apply_to_client = lambda self, client: None
        with pytest.raises(ClientCookieInjectionError, match="cookies were provided but none were injected"):
            account.make_client()
    finally:
        XSession.apply_to_client = original_apply


def test_make_client_loads_raw_env_cookies_when_account_has_none(monkeypatch):
    monkeypatch.setenv(
        "X_COOKIES",
        "auth_token=token123; ct0=csrf456; twid=u%3D1111111111111111111",
    )

    account = Account(
        username="user",
        password="pass",
        email="user@example.com",
        email_password="email_pass",
        user_agent="test-agent",
        active=True,
        locks={},
        stats={},
        headers={},
        cookies={},
        mfa_code=None,
        proxy=None,
        error_msg=None,
        last_used=None,
        _tx=None,
    )

    client = account.make_client()

    assert client.cookies["auth_token"] == "token123"
    assert client.cookies["ct0"] == "csrf456"
    assert client.cookies["twid"] == "u%3D1111111111111111111"
    assert client.headers["x-csrf-token"] == "csrf456"


def test_make_client_returns_cached_client_and_detects_recreation():
    account = Account(
        username="user",
        password="pass",
        email="user@example.com",
        email_password="email_pass",
        user_agent="test-agent",
        active=True,
        locks={},
        stats={},
        headers={},
        cookies={"auth_token": "token", "ct0": "csrf", "twid": "twid"},
        mfa_code=None,
        proxy=None,
        error_msg=None,
        last_used=None,
        _tx=None,
    )

    first_client = account.make_client()
    second_client = account.make_client()
    assert first_client is second_client

    with pytest.raises(ClientStateViolationError):
        account.make_client(proxy="http://proxy.example.com")
