import base64
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Callable, TypeVar

T = TypeVar("T")


class utc:
    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def from_iso(iso: str) -> datetime:
        return datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)

    @staticmethod
    def ts() -> int:
        return int(utc.now().timestamp())


async def gather(gen: AsyncGenerator[T, None]) -> list[T]:
    items = []
    async for x in gen:
        items.append(x)
    return items


def encode_params(obj: dict):
    res = {}
    for k, v in obj.items():
        if isinstance(v, dict):
            v = {a: b for a, b in v.items() if b is not None}
            v = json.dumps(v, separators=(",", ":"))

        res[k] = str(v)

    return res


def get_or(obj: dict, key: str, default_value: T = None) -> Any | T:
    for part in key.split("."):
        if part not in obj:
            return default_value
        obj = obj[part]
    return obj


def int_or(obj: dict, key: str, default_value: int | None = None):
    try:
        val = get_or(obj, key)
        return int(val) if val is not None else default_value
    except Exception:
        return default_value


# https://stackoverflow.com/a/43184871
def get_by_path(obj: dict, key: str, default=None):
    stack = [iter(obj.items())]
    while stack:
        for k, v in stack[-1]:
            if k == key:
                return v
            elif isinstance(v, dict):
                stack.append(iter(v.items()))
                break
            elif isinstance(v, list):
                stack.append(iter(enumerate(v)))
                break
        else:
            stack.pop()
    return default


def find_item(lst: list[T], fn: Callable[[T], bool]) -> T | None:
    for item in lst:
        if fn(item):
            return item
    return None


def find_or_fail(lst: list[T], fn: Callable[[T], bool]) -> T:
    item = find_item(lst, fn)
    if item is None:
        raise ValueError()
    return item


def find_obj(obj: dict, fn: Callable[[dict], bool]) -> Any | None:
    if not isinstance(obj, dict):
        return None

    if fn(obj):
        return obj

    for _, v in obj.items():
        if isinstance(v, dict):
            if res := find_obj(v, fn):
                return res
        elif isinstance(v, list):
            for x in v:
                if res := find_obj(x, fn):
                    return res

    return None


def get_typed_object(obj: dict, res: defaultdict[str, list]):
    obj_type = obj.get("__typename", None)
    if obj_type is not None:
        res[obj_type].append(obj)

    for _, v in obj.items():
        if isinstance(v, dict):
            get_typed_object(v, res)
        elif isinstance(v, list):
            for x in v:
                if isinstance(x, dict):
                    get_typed_object(x, res)

    return res


def to_old_obj(obj: dict):
    return {
        **obj,
        **obj["legacy"],
        "id_str": str(obj["rest_id"]),
        "id": int(obj["rest_id"]),
        "legacy": None,
    }


def to_old_rep(obj: dict) -> dict[str, dict]:
    tmp = get_typed_object(obj, defaultdict(list))

    tw1 = [x for x in tmp.get("Tweet", []) if "legacy" in x]
    tw1 = {str(x["rest_id"]): to_old_obj(x) for x in tw1}

    # https://github.com/vladkens/twscrape/issues/53
    tw2 = [x["tweet"] for x in tmp.get("TweetWithVisibilityResults", []) if "legacy" in x["tweet"]]
    tw2 = {str(x["rest_id"]): to_old_obj(x) for x in tw2}

    users = [x for x in tmp.get("User", []) if "legacy" in x and "id" in x]
    users = {str(x["rest_id"]): to_old_obj(x) for x in users}

    trends = [x for x in tmp.get("TimelineTrend", [])]
    trends = {x["name"]: x for x in trends}

    return {"tweets": {**tw1, **tw2}, "users": users, "trends": trends}


def print_table(rows: list[dict], hr_after=False):
    if not rows:
        return

    def prt(x):
        if isinstance(x, str):
            return x

        if isinstance(x, int):
            return f"{x:,}"

        if isinstance(x, datetime):
            return x.isoformat().split("+")[0].replace("T", " ")

        return str(x)

    keys = list(rows[0].keys())
    rows = [{k: k for k in keys}, *[{k: prt(x.get(k, "")) for k in keys} for x in rows]]
    colw = [max(len(x[k]) for x in rows) + 1 for k in keys]

    lines = []
    for row in rows:
        line = [f"{row[k]:<{colw[i]}}" for i, k in enumerate(keys)]
        lines.append(" ".join(line))

    max_len = max(len(x) for x in lines)
    # lines.insert(1, "─" * max_len)
    # lines.insert(0, "─" * max_len)
    print("\n".join(lines))
    if hr_after:
        print("-" * max_len)


class CookieConfigError(Exception):
    pass


def _cookie_value_preview(value: str) -> str:
    if not isinstance(value, str) or value == "":
        return ""
    return f"{value[:6]}..." if len(value) > 6 else f"{value}..."


def _normalize_cookie_payload(payload: object) -> dict[str, str]:
    if isinstance(payload, dict):
        return {str(k): str(v) for k, v in payload.items()}

    if isinstance(payload, list):
        return {str(item["name"]): str(item["value"]) for item in payload}

    raise ValueError("Invalid JSON cookie structure")


def parse_raw_cookie_string(raw: str) -> dict[str, str]:
    if not isinstance(raw, str):
        raise ValueError("Raw cookie string must be a string")

    try:
        raw = base64.b64decode(raw).decode()
    except Exception:
        pass

    try:
        payload = json.loads(raw)
        if isinstance(payload, dict) and "cookies" in payload:
            payload = payload["cookies"]
        return _normalize_cookie_payload(payload)
    except json.JSONDecodeError:
        try:
            pairs = [item.strip() for item in raw.split(";") if item.strip()]
            parsed = {}
            for item in pairs:
                if "=" not in item:
                    raise ValueError
                name, value = item.split("=", 1)
                parsed[name.strip()] = value
            return parsed
        except Exception:
            raise ValueError(f"Invalid cookie value: {raw}")


def _sanitize_env_preview(value: str) -> str:
    if not isinstance(value, str):
        return ""
    preview = value[:80]
    return preview.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def _detect_compose_source() -> str:
    compose_file = os.getenv("COMPOSE_FILE") or os.getenv("DOCKER_COMPOSE_FILE")
    if compose_file:
        return f"COMPOSE_FILE={compose_file}"

    compose_project = os.getenv("COMPOSE_PROJECT_NAME")
    if compose_project:
        return f"COMPOSE_PROJECT_NAME={compose_project}"

    for filename in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        if os.path.exists(filename):
            return filename

    return "unknown"


def validate_cookie_env() -> dict[str, str]:
    env_value = os.getenv("X_COOKIES_JSON")
    if env_value is not None:
        if env_value == "":
            raise CookieConfigError("X_COOKIES_JSON is defined but empty")

        try:
            payload = json.loads(env_value)
        except json.JSONDecodeError as err:
            raise CookieConfigError(f"X_COOKIES_JSON invalid JSON: {err}") from err

        if isinstance(payload, dict) and "cookies" in payload:
            payload = payload["cookies"]

        parsed_cookies = _normalize_cookie_payload(payload)
        source = "X_COOKIES_JSON"
    else:
        raw_cookies = os.getenv("X_COOKIES")
        if raw_cookies is None:
            raise CookieConfigError("X_COOKIES_JSON is not set and X_COOKIES is not set")

        parsed_cookies = parse_raw_cookie_string(raw_cookies)
        source = "X_COOKIES"

    if not parsed_cookies:
        raise CookieConfigError(f"{source} parsed to an empty cookie object")

    missing = [k for k in ("auth_token", "ct0") if k not in parsed_cookies]
    if missing:
        raise CookieConfigError(f"{source} missing required cookies: {missing}")

    return parsed_cookies


def _dump_runtime_env_info(logger):
    env_path = os.path.abspath(".env")
    compose_source = _detect_compose_source()

    logger.info("[RUNTIME_ENV_DUMP]")
    logger.info(f"cwd={os.getcwd()}")
    logger.info(f"env_file_path={env_path}")
    logger.info(f"env_file_exists={os.path.exists(env_path)}")
    logger.info(f"compose_env_source={compose_source}")
    logger.info(f"X_COOKIES_JSON_present={os.getenv('X_COOKIES_JSON') is not None}")


def log_cookie_config_diagnostics(logger):
    env_value = os.getenv("X_COOKIES_JSON")
    env_present = env_value is not None
    json_length = len(env_value) if env_present else 0
    parsed_cookies: dict[str, str] = {}
    payload_type = "<none>"
    payload_preview = ""

    if env_present:
        try:
            payload = json.loads(env_value)
            payload_type = type(payload).__name__
            if isinstance(payload, dict) and "cookies" in payload:
                payload = payload["cookies"]
            payload_preview = repr(payload)[:300]
            parsed_cookies = _normalize_cookie_payload(payload)
        except json.JSONDecodeError as err:
            payload_type = "invalid-json"
            payload_preview = repr(env_value[:300])
            logger.error(f"[COOKIE_OBJECT] invalid_json={err}")
        except ValueError:
            payload_type = type(payload).__name__ if "payload" in locals() else "unknown"
            payload_preview = repr(payload)[:300] if "payload" in locals() else ""
    else:
        raw_cookies = os.getenv("X_COOKIES")
        if raw_cookies:
            try:
                parsed_cookies = parse_raw_cookie_string(raw_cookies)
                payload_type = "raw-cookies"
                payload_preview = repr(raw_cookies)[:300]
            except Exception:
                parsed_cookies = {}
                payload_type = "raw-cookies"
                payload_preview = repr(raw_cookies)[:300]

    logger.info(f"[COOKIE_OBJECT] type={payload_type} preview={payload_preview}")
    logger.info("[X_COOKIE_DEBUG]")
    logger.info(f"env_present={env_present}")
    logger.info(f"env_preview={_sanitize_env_preview(env_value or '')}")
    logger.info(f"json_length={json_length}")
    logger.info(f"parsed_type={payload_type}")
    logger.info(f"parsed_cookie_count={len(parsed_cookies)}")

    cookie_keys = sorted(parsed_cookies.keys())
    auth_token_preview = _cookie_value_preview(parsed_cookies.get("auth_token", ""))
    ct0_preview = _cookie_value_preview(parsed_cookies.get("ct0", ""))

    logger.info(f"cookie_keys={cookie_keys}")
    logger.info(f"auth_token_preview={auth_token_preview}")
    logger.info(f"ct0_preview={ct0_preview}")
    _dump_runtime_env_info(logger)


def parse_cookies(val: str) -> dict[str, str]:
    return parse_raw_cookie_string(val)


def get_env_bool(key: str, default_val: bool = False) -> bool:
    val = os.getenv(key)
    if val is None:
        return default_val
    return val.lower() in ("1", "true", "yes")
