import httpx
import pytest

from twscrape.xclid import (
    ClientStateViolationError,
    InvalidAccountStateError,
    XClIdGen,
    XClIdGenError,
    XDebugReason,
    classify_x_response,
    get_scripts_list,
    get_tw_page_text,
)


def test_get_scripts_list_raises_xclid_error_on_missing_markers():
    with pytest.raises(XClIdGenError):
        list(get_scripts_list("<html>No xclid markers here</html>"))


def test_get_scripts_list_parses_valid_markers():
    html = 'e=>e+"."+{"abc":"123"}[e]+"a.js"'
    scripts = list(get_scripts_list(html))
    assert scripts == ["https://abs.twimg.com/responsive-web/client-web/abc.123a.js"]


@pytest.mark.asyncio
async def test_get_tw_page_text_detects_login_page():
    class FakeClient:
        cookies = {"auth_token": "token", "ct0": "csrf"}
        headers = {"user-agent": "test-agent"}

        async def get(self, url):
            request = httpx.Request("GET", url)
            return httpx.Response(
                200,
                request=request,
                text="<html><head><title>Log in to X</title></head><body>Please log in</body></html>",
            )

    with pytest.raises(XClIdGenError, match="cookie_invalid"):
        await get_tw_page_text("https://x.com/elonmusk", clt=FakeClient())


@pytest.mark.asyncio
async def test_get_tw_page_text_detects_waf_page():
    class FakeClient:
        cookies = {"auth_token": "token", "ct0": "csrf"}
        headers = {"user-agent": "test-agent"}

        async def get(self, url):
            request = httpx.Request("GET", url)
            return httpx.Response(
                200,
                request=request,
                text="<html><body>Access denied. Please verify you\'re human.</body></html>",
            )

    with pytest.raises(XClIdGenError, match="waf_block"):
        await get_tw_page_text("https://x.com/elonmusk", clt=FakeClient())


@pytest.mark.asyncio
async def test_get_tw_page_text_invalid_account_state_raises():
    class FakeClient:
        cookies = {"twid": "value"}
        headers = {"user-agent": "test-agent"}

        async def get(self, url):
            raise AssertionError("Should not request network on invalid account state")

    with pytest.raises(InvalidAccountStateError, match="Account client missing critical state"):
        await get_tw_page_text("https://x.com/elonmusk", clt=FakeClient())


@pytest.mark.asyncio
async def test_xclid_create_does_not_guest_fallback_by_default(monkeypatch):
    class AccountClient:
        cookies = {"auth_token": "token", "ct0": "csrf"}
        headers = {"user-agent": "account-agent"}

        async def get(self, url):
            request = httpx.Request("GET", url)
            return httpx.Response(
                200,
                request=request,
                text="<html><head><title>Log in to X</title></head><body>Please log in</body></html>",
            )

    def fake_make_client(proxy=None):
        class GuestClient:
            cookies = {}
            headers = {"user-agent": "guest-agent"}

            async def __aenter__(self):
                self.__guest_client = True
                self.__proxy = proxy
                self.__account_username = "<guest>"
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def get(self, url):
                request = httpx.Request("GET", url)
                return httpx.Response(200, request=request, text="<html></html>")

        return GuestClient()

    monkeypatch.setattr("twscrape.xclid._make_client", fake_make_client)

    async def fake_load_keys(soup):
        return [1, 2, 3], "anim-key"

    monkeypatch.setattr("twscrape.xclid.load_keys", fake_load_keys)

    with pytest.raises(XClIdGenError):
        await XClIdGen.create(clt=AccountClient())


@pytest.mark.asyncio
async def test_xclid_create_allows_guest_fallback_when_guest_mode_true(monkeypatch):
    class AccountClient:
        cookies = {"auth_token": "token", "ct0": "csrf"}
        headers = {"user-agent": "account-agent"}

        async def get(self, url):
            request = httpx.Request("GET", url)
            return httpx.Response(
                200,
                request=request,
                text="<html><head><title>Log in to X</title></head><body>Please log in</body></html>",
            )

    class GuestClient:
        cookies = {}
        headers = {"user-agent": "guest-agent"}

        async def get(self, url):
            request = httpx.Request("GET", url)
            return httpx.Response(200, request=request, text="<html></html>")

    def fake_make_client(proxy=None):
        class GuestClientCtx(GuestClient):
            async def __aenter__(self):
                self._guest_client = True
                self.__proxy = proxy
                self.__account_username = "<guest>"
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        return GuestClientCtx()

    monkeypatch.setenv("GUEST_MODE", "true")
    monkeypatch.setattr("twscrape.xclid._make_client", fake_make_client)

    async def fake_load_keys(soup):
        return [1, 2, 3], "anim-key"

    monkeypatch.setattr("twscrape.xclid.load_keys", fake_load_keys)

    gen = await XClIdGen.create(clt=AccountClient())
    assert hasattr(gen, "calc")


def test_401_is_detected():
    assert classify_x_response(401, "") == XDebugReason.AUTH_401


def test_login_html_detected():
    assert classify_x_response(200, "<html>login</html>") == XDebugReason.COOKIE_INVALID


def test_challenge_html_detected():
    assert classify_x_response(200, "<html>challenge</html>") == XDebugReason.WAF_BLOCK
