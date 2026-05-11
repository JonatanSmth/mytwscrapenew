import base64
import hashlib
import json
import math
import random
import re
import time

import bs4
import httpx
from fake_useragent import UserAgent

from .logger import logger


class XClIdGenError(Exception):
    """Raised when x.com client transaction id generation fails."""


class InvalidXSessionError(XClIdGenError):
    """Raised when x.com responds with a login or WAF page instead of a valid session."""


def _split_or_raise(text: str, sep: str, message: str) -> str:
    idx = text.find(sep)
    if idx == -1:
        raise XClIdGenError(message)
    start = idx + len(sep)
    return text[start:]


def safe_find_between(text: str, left: str, right: str) -> str | None:
    start = text.find(left)
    if start == -1:
        return None
    start += len(left)
    end = text.find(right, start)
    if end == -1:
        return None
    return text[start:end]


def detect_invalid_x_page(text: str) -> str | None:
    lower = text.lower()
    if "captcha" in lower or "verify you're human" in lower or "complete the security check" in lower:
        return "WAF / bot challenge page"
    if "access denied" in lower or "blocked" in lower or "suspicious activity" in lower:
        return "WAF / access denied page"
    if re.search(r"<title[^>]*>.*login.*</title>", text, re.I) or "log in to x" in lower or "sign in" in lower:
        return "Login page"
    return None


def _make_client() -> httpx.AsyncClient:
    headers = {"user-agent": UserAgent().chrome}
    return httpx.AsyncClient(headers=headers, follow_redirects=True)


async def get_tw_page_text(url: str, clt: httpx.AsyncClient | None = None):
    clt = clt or _make_client()
    rep = await clt.get(url)

    rep.raise_for_status()
    page_text = rep.text
    if reason := detect_invalid_x_page(page_text):
        logger.error(
            f"Invalid X HTML response detected ({reason}). HTML preview: {page_text[:500]!r}"
        )
        raise InvalidXSessionError(f"Invalid X HTML response: {reason}")

    if ">document.location =" not in page_text:
        return page_text

    redirect_url = safe_find_between(page_text, 'document.location = "', '"')
    if redirect_url is None:
        logger.error(
            f"Failed to parse x.com redirect location. HTML preview: {page_text[:500]!r}"
        )
        raise XClIdGenError("Failed to parse x.com redirect location")

    rep = await clt.get(redirect_url)
    rep.raise_for_status()
    page_text = rep.text
    if reason := detect_invalid_x_page(page_text):
        logger.error(
            f"Invalid X HTML response detected after redirect ({reason}). HTML preview: {page_text[:500]!r}"
        )
        raise InvalidXSessionError(f"Invalid X HTML response after redirect: {reason}")

    if 'action="https://x.com/x/migrate" method="post"' not in page_text:
        return page_text

    soup = bs4.BeautifulSoup(page_text, "html.parser")
    data = {
        tag["name"]: tag["value"]
        for tag in soup.find_all("input", attrs={"name": True, "value": True})
    }

    if not data:
        logger.error(
            f"Failed to parse x.com migrate form inputs. HTML preview: {page_text[:500]!r}"
        )
        raise XClIdGenError("Failed to parse x.com migrate form inputs")

    rep = await clt.post("https://x.com/x/migrate", json=data)
    rep.raise_for_status()

    return rep.text


def script_url(k: str, v: str):
    return f"https://abs.twimg.com/responsive-web/client-web/{k}.{v}.js"


def get_scripts_list(text: str):
    if detect_invalid_x_page(text):
        raise XClIdGenError("Invalid X HTML response while extracting scripts")

    marker_start = 'e=>e+"."+'
    marker_end = '[e]+"a.js"'
    start_idx = text.find(marker_start)
    if start_idx == -1:
        logger.error(f"Failed to parse XClientTxId script list markers. HTML preview: {text[:500]!r}")
        raise XClIdGenError("Couldn't parse XClientTxId script list markers")

    end_idx = text.find(marker_end, start_idx)
    if end_idx == -1:
        logger.error(f"Failed to parse XClientTxId script list markers. HTML preview: {text[:500]!r}")
        raise XClIdGenError("Couldn't parse XClientTxId script list markers")

    scripts = text[start_idx + len(marker_start) : end_idx]

    try:
        data = json.loads(scripts)

    except json.decoder.JSONDecodeError:
        # 🔥 FIX: repair JS-style object keys -> valid JSON
        fixed_scripts = re.sub(r"([{,]\s*)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:", r'\1"\2":', scripts)

        try:
            data = json.loads(fixed_scripts)
        except json.decoder.JSONDecodeError as e:
            raise XClIdGenError("Failed to parse scripts (even after repair)") from e

    for k, v in data.items():
        yield script_url(k, f"{v}a")


# MARK: XClientTxId parsing

INDICES_REGEX = re.compile(r"(\(\w{1}\[(\d{1,2})\],\s*16\))+", flags=(re.VERBOSE | re.MULTILINE))


class Cubic:
    def __init__(self, curves: list[float]):
        self.curves = curves

    def get_value(self, time: float) -> float:
        start_gradient = end_gradient = start = mid = 0.0
        end = 1.0

        if time <= 0.0:
            if self.curves[0] > 0.0:
                start_gradient = self.curves[1] / self.curves[0]
            elif self.curves[1] == 0.0 and self.curves[2] > 0.0:
                start_gradient = self.curves[3] / self.curves[2]
            return start_gradient * time

        if time >= 1.0:
            if self.curves[2] < 1.0:
                end_gradient = (self.curves[3] - 1.0) / (self.curves[2] - 1.0)
            elif self.curves[2] == 1.0 and self.curves[0] < 1.0:
                end_gradient = (self.curves[1] - 1.0) / (self.curves[0] - 1.0)
            return 1.0 + end_gradient * (time - 1.0)

        while start < end:
            mid = (start + end) / 2
            x_est = self.calculate(self.curves[0], self.curves[2], mid)
            if abs(time - x_est) < 0.00001:
                return self.calculate(self.curves[1], self.curves[3], mid)
            if x_est < time:
                start = mid
            else:
                end = mid
        return self.calculate(self.curves[1], self.curves[3], mid)

    @staticmethod
    def calculate(a: float, b: float, m: float) -> float:
        return 3.0 * a * (1 - m) * (1 - m) * m + 3.0 * b * (1 - m) * m * m + m * m * m


def interpolate(from_list: list[float], to_list: list[float], f: float):
    assert len(from_list) == len(to_list)
    return [a * (1 - f) + b * f for a, b in zip(from_list, to_list)]


def get_rotation_matrix(rotation: float):
    rad = math.radians(rotation)
    return [math.cos(rad), -math.sin(rad), math.sin(rad), math.cos(rad)]


def solve(value: float, min_val: float, max_val: float, rounding: bool):
    result = value * (max_val - min_val) / 255 + min_val
    return math.floor(result) if rounding else round(result, 2)


def float_to_hex(x):
    result = []
    quotient = int(x)
    fraction = x - quotient

    while quotient > 0:
        quotient = int(x / 16)
        remainder = int(x - (float(quotient) * 16))

        if remainder > 9:
            result.insert(0, chr(remainder + 55))
        else:
            result.insert(0, str(remainder))

        x = float(quotient)

    if fraction == 0:
        return "".join(result)

    result.append(".")

    while fraction > 0:
        fraction *= 16
        integer = int(fraction)
        fraction -= float(integer)

        if integer > 9:
            result.append(chr(integer + 55))
        else:
            result.append(str(integer))

    return "".join(result)


def cacl_anim_key(frames: list[float], target_time: float) -> str:
    from_color = [*frames[:3], 1]
    to_color = [*frames[3:6], 1]
    from_rotation = [0.0]
    to_rotation = [solve(frames[6], 60.0, 360.0, True)]

    frames = frames[7:]
    curves = [solve(x, -1.0 if i % 2 else 0.0, 1.0, False) for i, x in enumerate(frames)]
    val = Cubic(curves).get_value(target_time)

    color = interpolate(from_color, to_color, val)
    color = [value if value > 0 else 0 for value in color]
    rotation = interpolate(from_rotation, to_rotation, val)

    matrix = get_rotation_matrix(rotation[0])
    str_arr = [format(round(value), "x") for value in color[:-1]]

    for value in matrix:
        rounded = abs(round(value, 2))
        hex_value = float_to_hex(rounded)
        str_arr.append(
            f"0{hex_value}".lower()
            if hex_value.startswith(".")
            else hex_value
            if hex_value
            else "0"
        )

    str_arr.extend(["0", "0"])
    return re.sub(r"[.-]", "", "".join(str_arr))


def parse_vk_bytes(soup: bs4.BeautifulSoup) -> list[int]:
    el = soup.find("meta", {"name": "twitter-site-verification", "content": True})
    el = str(el.get("content")) if el and isinstance(el, bs4.Tag) else None
    if not el:
        raise XClIdGenError("Couldn't get XClientTxId key bytes")

    return list(base64.b64decode(bytes(el, "utf-8")))


async def parse_anim_idx(text: str) -> list[int]:
    scripts = list(get_scripts_list(text))
    scripts = [x for x in scripts if "/ondemand.s." in x]
    if not scripts:
        raise XClIdGenError("Couldn't get XClientTxId scripts")

    text = await get_tw_page_text(scripts[0])

    items = [int(x.group(2)) for x in INDICES_REGEX.finditer(text)]
    if not items:
        logger.error(f"Couldn't get XClientTxId indices. JS preview: {text[:500]!r}")
        raise XClIdGenError("Couldn't get XClientTxId indices")

    return items


def parse_anim_arr(soup: bs4.BeautifulSoup, vk_bytes: list[int]) -> list[list[float]]:
    els = list(soup.select("svg[id^='loading-x-anim'] g:first-child path:nth-child(2)"))
    els = [str(x.get("d") or "").strip() for x in els]
    if not els:
        raise XClIdGenError("Couldn't get XClientTxId animation array")

    try:
        idx = vk_bytes[5] % len(els)
        dat = els[idx][9:].split("C")
        arr = [list(map(float, re.sub(r"[^\d]+", " ", x).split())) for x in dat]
    except Exception as e:
        raise XClIdGenError("Couldn't parse XClientTxId animation array") from e

    return arr


async def load_keys(soup: bs4.BeautifulSoup) -> tuple[list[int], str]:
    try:
        anim_idx = await parse_anim_idx(str(soup))
        vk_bytes = parse_vk_bytes(soup)
        anim_arr = parse_anim_arr(soup, vk_bytes)
    except XClIdGenError:
        raise
    except Exception as e:
        raise XClIdGenError("Failed to load XClIdGen keys") from e

    frame_time = 1
    for x in anim_idx[1:]:
        frame_time *= vk_bytes[x] % 16

    frame_idx = vk_bytes[anim_idx[0]] % 16
    frame_row = anim_arr[frame_idx]
    frame_dur = float(frame_time) / 4096

    anim_key = cacl_anim_key(frame_row, frame_dur)
    return vk_bytes, anim_key


class XClIdGen:
    @staticmethod
    async def create(clt: httpx.AsyncClient | None = None) -> "XClIdGen":
        try:
            text = await get_tw_page_text("https://x.com/elonmusk", clt=clt)
            soup = bs4.BeautifulSoup(text, "html.parser")
            vk_bytes, anim_key = await load_keys(soup)
            return XClIdGen(vk_bytes, anim_key)
        except XClIdGenError:
            raise
        except Exception as e:
            raise XClIdGenError("Failed to generate XClId") from e

    def __init__(self, vk_bytes: list[int], anim_key: str):
        self.vk_bytes = vk_bytes
        self.anim_key = anim_key

    def calc(self, method: str, path: str) -> str:
        ts = math.floor((time.time() * 1000 - 1682924400 * 1000) / 1000)
        ts_bytes = [(ts >> (i * 8)) & 0xFF for i in range(4)]

        dkw, drn = "obfiowerehiring", 3
        pld = f"{method.upper()}!{path}!{ts}{dkw}{self.anim_key}"
        pld = list(hashlib.sha256(pld.encode()).digest())
        pld = [*self.vk_bytes, *ts_bytes, *pld[:16], drn]

        num = random.randint(0, 255)
        pld = bytearray([num, *[x ^ num for x in pld]])
        return base64.b64encode(pld).decode("utf-8").strip("=")
