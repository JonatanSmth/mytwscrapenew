import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime

from httpx import AsyncClient, AsyncHTTPTransport

from .logger import logger
from .models import JSONTrait
from .utils import _normalize_cookie_payload, get_env_bool, log_cookie_config_diagnostics, parse_raw_cookie_string, utc, validate_cookie_env
from .xclid import ClientStateViolationError


@dataclass
class XSession:
    cookies: dict[str, str] | list[dict[str, str]]
    headers: dict[str, str]
    proxy: str | None = None
    last_validated: int | None = None

    def __post_init__(self):
        if isinstance(self.cookies, list):
            self.cookies = _normalize_cookie_payload(self.cookies)
        elif not isinstance(self.cookies, dict):
            raise ValueError("XSession cookies must be a dict or a list of cookie objects")

    def apply_to_client(self, client: AsyncClient):
        if isinstance(self.cookies, list):
            self.cookies = _normalize_cookie_payload(self.cookies)

        if not self.cookies:
            client.headers.update(self.headers)
            return

        cookie_mapping = {str(k): str(v) for k, v in self.cookies.items()}
        logger.info(f"[COOKIE_INJECTION_PRE] type={type(self.cookies).__name__} repr={repr(self.cookies)}")

        for name, value in cookie_mapping.items():
            client.cookies.set(name, value, domain=".x.com", path="/")

        injected_items = list(client.cookies.items())
        logger.info(f"[HTTPX_COOKIE_JAR] items={injected_items}")

        if "auth_token" not in client.cookies or "ct0" not in client.cookies:
            missing = [k for k in ("auth_token", "ct0") if k not in client.cookies]
            raise CookieInjectionFailure(
                f"Account HTTPX cookie jar is missing required cookies after injection: {missing}"
            )

        client.headers.update(self.headers)

        if "ct0" in client.cookies:
            client.headers["x-csrf-token"] = client.cookies["ct0"]
        elif self.cookies:
            logger.warning("Session cookies provided but missing ct0; session will be invalid until ct0 is present")

TOKEN = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"


class ClientCookieInjectionError(Exception):
    pass


class CookieInjectionFailure(ClientCookieInjectionError):
    pass


@dataclass
class Account(JSONTrait):
    username: str
    password: str
    email: str
    email_password: str
    user_agent: str
    active: bool
    locks: dict[str, datetime] = field(default_factory=dict)  # queue: datetime
    stats: dict[str, int] = field(default_factory=dict)  # queue: requests
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    mfa_code: str | None = None
    proxy: str | None = None
    error_msg: str | None = None
    last_used: datetime | None = None
    _tx: str | None = None
    _http_client: AsyncClient | None = field(default=None, init=False, repr=False)
    _http_client_instance_id: str | None = field(default=None, init=False, repr=False)
    _http_client_proxy: str | None = field(default=None, init=False, repr=False)

    @staticmethod
    def from_rs(rs: sqlite3.Row):
        doc = dict(rs)
        doc["locks"] = {k: utc.from_iso(v) for k, v in json.loads(doc["locks"]).items()}
        doc["stats"] = {k: v for k, v in json.loads(doc["stats"]).items() if isinstance(v, int)}
        doc["headers"] = json.loads(doc["headers"])
        doc["cookies"] = _normalize_cookie_payload(json.loads(doc["cookies"]))
        doc["active"] = bool(doc["active"])
        doc["last_used"] = utc.from_iso(doc["last_used"]) if doc["last_used"] else None
        return Account(**doc)

    def to_rs(self):
        rs = asdict(self)
        for key in ("_http_client", "_http_client_instance_id", "_http_client_proxy"):
            rs.pop(key, None)
        rs["locks"] = json.dumps(rs["locks"], default=lambda x: x.isoformat())
        rs["stats"] = json.dumps(rs["stats"])
        rs["headers"] = json.dumps(rs["headers"])
        rs["cookies"] = json.dumps(rs["cookies"])
        rs["last_used"] = rs["last_used"].isoformat() if rs["last_used"] else None
        return rs

    def make_client(self, proxy: str | None = None) -> AsyncClient:
        if os.getenv("X_COOKIES_JSON") is not None:
            try:
                validate_cookie_env()
            except CookieConfigError as err:
                logger.error(f"X_COOKIES_JSON validation failed: {err}")
                raise

        log_cookie_config_diagnostics(logger)

        if not self.cookies and os.getenv("X_COOKIES") is not None:
            try:
                parsed_cookies = parse_raw_cookie_string(os.getenv("X_COOKIES"))
                if parsed_cookies:
                    self.cookies = parsed_cookies
                    logger.info(
                        f"[COOKIE_ENV_FALLBACK] loaded {len(parsed_cookies)} cookies from X_COOKIES env"
                    )
            except Exception as err:
                logger.warning(f"[COOKIE_ENV_FALLBACK] failed to parse X_COOKIES: {err}")

        proxies = [proxy, os.getenv("TWS_PROXY"), self.proxy]
        proxies = [x for x in proxies if x is not None]
        proxy = proxies[0] if proxies else None

        if self._http_client is not None:
            if proxy != self._http_client_proxy:
                raise ClientStateViolationError(
                    f"Attempt to recreate HTTP client for {self.username} with a different proxy. "
                    f"existing_proxy={self._http_client_proxy!r}, requested_proxy={proxy!r}"
                )
            return self._http_client

        transport = AsyncHTTPTransport(retries=3)
        client = AsyncClient(proxy=proxy, follow_redirects=True, transport=transport)

        logger.info(f"[COOKIE_INJECTION_ACCOUNT] type={type(self.cookies).__name__} repr={repr(self.cookies)}")
        XSession(self.cookies, self.headers, proxy=self.proxy).apply_to_client(client)

        if self.cookies and len(client.cookies) == 0:
            raise ClientCookieInjectionError(
                f"Account {self.username}: cookies were provided but none were injected into the HTTP client"
            )

        if self.cookies:
            logger.debug(
                f"Account {self.username}: client initialized with {len(self.cookies)} cookies; "
                f"ct0_present={'ct0' in self.cookies}; keys={sorted(self.cookies.keys())}"
            )
        else:
            logger.debug(f"Account {self.username}: client initialized without cookies")

        # default settings
        client.headers["user-agent"] = self.user_agent
        client.headers["content-type"] = "application/json"
        client.headers["authorization"] = TOKEN
        client.headers["x-twitter-active-user"] = "yes"
        client.headers["x-twitter-client-language"] = "en"

        client.__proxy = proxy
        client.__account_username = self.username
        client.__guest_client = False
        client.__instance_id = uuid.uuid4().hex

        self._http_client = client
        self._http_client_instance_id = client.__instance_id
        self._http_client_proxy = proxy

        if get_env_bool("XCLIENT_DEBUG"):
            logger.info(
                f"[XCLIENT_STATE] account={self.username} client_type=account cookie_count={len(self.cookies)} "
                f"cookies={sorted(self.cookies.keys())} ct0={'ct0' in self.cookies} auth_token={'auth_token' in self.cookies} "
                f"fingerprint={bool(client.headers.get('x-twitter-client-language'))} ua={client.headers.get('user-agent', '')} "
                f"proxy={proxy or 'none'} request_url=<not requested yet>"
            )

        return client
