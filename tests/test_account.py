from twscrape.account import Account


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
