import httpx
import pytest

from twscrape.xclid import XClIdGenError, get_scripts_list, get_tw_page_text


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
        async def get(self, url):
            request = httpx.Request("GET", url)
            return httpx.Response(
                200,
                request=request,
                text="<html><head><title>Log in to X</title></head><body>Please log in</body></html>",
            )

    with pytest.raises(XClIdGenError, match="Login page"):
        await get_tw_page_text("https://x.com/elonmusk", clt=FakeClient())


@pytest.mark.asyncio
async def test_get_tw_page_text_detects_waf_page():
    class FakeClient:
        async def get(self, url):
            request = httpx.Request("GET", url)
            return httpx.Response(
                200,
                request=request,
                text="<html><body>Access denied. Please verify you\'re human.</body></html>",
            )

    with pytest.raises(XClIdGenError, match="WAF"):
        await get_tw_page_text("https://x.com/elonmusk", clt=FakeClient())
