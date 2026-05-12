import pytest

from twscrape.account import Account, ClientCookieInjectionError, XSession
from twscrape.xclid import ClientStateViolationError


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
