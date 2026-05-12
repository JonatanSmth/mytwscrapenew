import pytest

from twscrape.utils import log_cookie_config_diagnostics, parse_cookies


class DummyLogger:
    def __init__(self):
        self.messages = []

    def info(self, msg, *args, **kwargs):
        self.messages.append(msg % args if args else msg)

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


def test_cookies_parse():
    val = "abc=123; def=456; ghi=789"
    assert parse_cookies(val) == {"abc": "123", "def": "456", "ghi": "789"}

    val = '{"abc": "123", "def": "456", "ghi": "789"}'
    assert parse_cookies(val) == {"abc": "123", "def": "456", "ghi": "789"}

    val = '[{"name": "abc", "value": "123"}, {"name": "def", "value": "456"}, {"name": "ghi", "value": "789"}]'
    assert parse_cookies(val) == {"abc": "123", "def": "456", "ghi": "789"}

    val = "eyJhYmMiOiAiMTIzIiwgImRlZiI6ICI0NTYiLCAiZ2hpIjogIjc4OSJ9"
    assert parse_cookies(val) == {"abc": "123", "def": "456", "ghi": "789"}

    val = "W3sibmFtZSI6ICJhYmMiLCAidmFsdWUiOiAiMTIzIn0sIHsibmFtZSI6ICJkZWYiLCAidmFsdWUiOiAiNDU2In0sIHsibmFtZSI6ICJnaGkiLCAidmFsdWUiOiAiNzg5In1d"
    assert parse_cookies(val) == {"abc": "123", "def": "456", "ghi": "789"}

    val = '{"cookies": {"abc": "123", "def": "456", "ghi": "789"}}'
    assert parse_cookies(val) == {"abc": "123", "def": "456", "ghi": "789"}

    with pytest.raises(ValueError, match=r"Invalid cookie value: .+"):
        val = "{invalid}"
        assert parse_cookies(val) == {}


def test_cookie_config_diagnostics_logs_runtime_cookie_object(monkeypatch):
    monkeypatch.setenv(
        "X_COOKIES_JSON",
        '{"cookies": [{"name": "auth_token", "value": "token"}, {"name": "ct0", "value": "csrf"}]}',
    )
    logger = DummyLogger()
    log_cookie_config_diagnostics(logger)

    assert any("[X_COOKIE_DEBUG]" in message for message in logger.messages)
    assert any("[COOKIE_OBJECT]" in message for message in logger.messages)
    assert any("env_present=True" in message for message in logger.messages)
    assert any("cookie_keys=['auth_token', 'ct0']" in message or "cookie_keys=['ct0', 'auth_token']" in message for message in logger.messages)
