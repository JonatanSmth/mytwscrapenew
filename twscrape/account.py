import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime

from httpx import AsyncClient, AsyncHTTPTransport

from .logger import logger
from .models import JSONTrait
from .utils import get_env_bool, utc
from .xclid import ClientStateViolationError


@dataclass
class XSession:
    cookies: dict[str, str]
    headers: dict[str, str]
    proxy: str | None = None
    last_validated: int | None = None

    def apply_to_client(self, client: AsyncClient):
        for name, value in self.cookies.items():
            client.cookies.set(name, value)
        client.headers.update(self.headers)

        if "ct0" in client.cookies:
            client.headers["x-csrf-token"] = client.cookies["ct0"]
        elif self.cookies:
            logger.warning("Session cookies provided but missing ct0; session will be invalid until ct0 is present")

TOKEN = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"


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
        doc["cookies"] = json.loads(doc["cookies"])
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

        # saved from previous usage
        XSession(self.cookies, self.headers, proxy=self.proxy).apply_to_client(client)

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
                "[XCLIENT_STATE] account=%s client_type=account cookie_count=%s cookies=%s "
                "ct0=%s auth_token=%s fingerprint=%s ua=%s proxy=%s request_url=%s",
                self.username,
                len(self.cookies),
                sorted(self.cookies.keys()),
                'ct0' in self.cookies,
                'auth_token' in self.cookies,
                bool(client.headers.get("x-twitter-client-language")),
                client.headers.get("user-agent", ""),
                proxy or "none",
                "<not requested yet>",
            )

        return client
