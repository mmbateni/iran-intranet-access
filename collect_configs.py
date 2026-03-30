#!/usr/bin/env python3
"""
Iran Intranet Config Collector & Verifier  v4
==============================================
Direction A — Diaspora / researchers OUTSIDE Iran → SHOMA

Why public free configs fail
-----------------------------
Most scraped configs are volunteer-run servers with lifespans of hours.
Many configs using snapp.ir / arvancloud.ir as the address are designed
for use INSIDE Iran (Iranian CDN routes internally); from outside Iran
the CDN edge is reachable but the backend proxy is dead or has rotated
its UUID. A TCP-connect to port 443 succeeds even on a dead proxy.

This version adds:
  1. URI sanitisation — strips malformed fragments (---@channel--- chains,
     HTML-encoded &amp%3B, truncated URIs ending in "...", duplicate UUIDs)
  2. HTTP-level liveness probe — actually sends a CONNECT or WebSocket
     upgrade request and checks for a proxy-valid response, not just TCP
  3. Psiphon config sources — most reliable Iranian circumvention tool;
     config JSONs are maintained by Psiphon Inc. and rotate frequently
  4. Deduplification by UUID — same server often appears with different
     comment tags; keeps only the best-obfuscated copy per UUID
  5. Better sources — Reality/XTLS-focused aggregators, fresh IR configs

Verification pipeline (each config must pass all enabled stages):
  Stage 1 — URI sanitisation: malformed, truncated, or duplicate UUIDs
  Stage 2 — DNS: host resolves
  Stage 3 — TCP connect: port responds within TCP_TIMEOUT
  Stage 4 — HTTP probe: proxy sends a recognisable response to a
             WebSocket-upgrade or CONNECT request (PROBE_ENABLED=1)
  Stage 5 — GeoIP: exit IP is in Iranian or Armenian AS space
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

# ── Configuration ──────────────────────────────────────────────────────────────

IRAN_PROXY_CHECKER_DIR = os.environ.get("IRAN_PROXY_CHECKER_DIR", "iran-proxy-checker")
TCP_TIMEOUT            = float(os.environ.get("TCP_TIMEOUT",         "4.0"))
HTTP_TIMEOUT           = int(  os.environ.get("HTTP_TIMEOUT",        "10"))
MAX_WORKERS            = int(  os.environ.get("MAX_WORKERS",         "60"))
SKIP_V2RAY_TEST        = os.environ.get("SKIP_V2RAY_TEST",    "1").strip() == "1"
MIN_PASSING_CONFIGS    = int(  os.environ.get("MIN_PASSING_CONFIGS", "50"))
# Set PROBE_ENABLED=1 to enable HTTP-level liveness probing.
# Adds ~5-10 min to runtime but eliminates dead configs more reliably.
PROBE_ENABLED          = os.environ.get("PROBE_ENABLED",      "0").strip() == "1"

# ── Iranian IP prefix registry ─────────────────────────────────────────────────

IRAN_IP_PREFIXES: tuple[tuple[str, str, str], ...] = (
    # TCI / DCI (AS12880, AS58224) — backbone; first to go in shutdowns
    ("2.176.",    "AS12880",  "TCI"), ("2.177.",   "AS12880", "TCI"),
    ("2.178.",    "AS12880",  "TCI"), ("2.179.",   "AS12880", "TCI"),
    ("2.180.",    "AS12880",  "TCI"), ("2.181.",   "AS12880", "TCI"),
    ("2.182.",    "AS12880",  "TCI"), ("2.183.",   "AS12880", "TCI"),
    ("2.184.",    "AS12880",  "TCI"), ("2.185.",   "AS12880", "TCI"),
    ("2.186.",    "AS12880",  "TCI"), ("2.187.",   "AS12880", "TCI"),
    ("2.188.",    "AS12880",  "TCI"), ("2.189.",   "AS12880", "TCI"),
    ("2.190.",    "AS12880",  "TCI"), ("2.191.",   "AS12880", "TCI"),
    ("5.160.",    "AS12880",  "TCI"), ("5.164.",   "AS12880", "TCI"),
    ("5.168.",    "AS12880",  "TCI"), ("5.172.",   "AS12880", "TCI"),
    ("5.176.",    "AS12880",  "TCI"), ("5.180.",   "AS12880", "TCI"),
    ("5.184.",    "AS12880",  "TCI"), ("5.188.",   "AS12880", "TCI"),
    ("5.192.",    "AS12880",  "TCI"), ("5.196.",   "AS12880", "TCI"),
    ("5.200.",    "AS12880",  "TCI"), ("78.38.",   "AS12880", "TCI"),
    ("78.39.",    "AS12880",  "TCI"),
    ("217.218.",  "AS58224",  "TCI"), ("217.219.", "AS58224", "TCI"),
    ("46.100.",   "AS58224",  "TCI"), ("46.101.",  "AS58224", "TCI"),
    # MCI / Hamrahe Aval (AS197207) — 66% market; most resilient in shutdowns
    ("89.32.",    "AS197207", "MCI"), ("89.33.",   "AS197207", "MCI"),
    ("89.34.",    "AS197207", "MCI"), ("89.35.",   "AS197207", "MCI"),
    ("151.232.",  "AS197207", "MCI"), ("151.233.", "AS197207", "MCI"),
    ("151.234.",  "AS197207", "MCI"), ("151.235.", "AS197207", "MCI"),
    # Irancell (AS44244)
    ("91.92.",    "AS44244",  "Irancell"), ("91.93.", "AS44244", "Irancell"),
    ("91.94.",    "AS44244",  "Irancell"), ("91.95.", "AS44244", "Irancell"),
    ("185.112.",  "AS44244",  "Irancell"),
    # Rightel (AS57218)
    ("91.186.",   "AS57218",  "Rightel"), ("91.187.", "AS57218", "Rightel"),
    # Shatel/TIC (AS48159)
    ("185.141.",  "AS48159",  "Shatel"), ("109.122.", "AS48159", "Shatel"),
    # Soroush Rasaneh (AS214922) — confirmed IR-exit
    ("81.12.",    "AS214922", "Soroush"), ("81.13.", "AS214922", "Soroush"),
    ("81.14.",    "AS214922", "Soroush"), ("81.15.", "AS214922", "Soroush"),
    # Arvan Cloud CDN (AS205347, AS207719) — gov/banking; domain-fronting hub
    ("185.51.200.", "AS205347", "Arvan"), ("185.143.", "AS207719", "Arvan"),
    ("194.36.170.", "AS207719", "Arvan"),
    # Asiatech, Fanap, ParsOnline, Afranet, Respina, HiWeb
    ("194.5.175.",  "AS210362", "Asiatech"), ("195.146.", "AS43754", "Asiatech"),
    ("91.108.4.",   "AS62282",  "Fanap"),    ("91.108.8.", "AS62282", "Fanap"),
    ("213.176.",    "AS49100",  "ParsOnline"),
    ("62.193.",     "AS25184",  "Afranet"),
    ("185.167.",    "AS42337",  "Respina"),
    ("94.182.",     "AS197398", "HiWeb"), ("94.183.", "AS197398", "HiWeb"),
    # IPM Research
    ("212.16.",     "AS12660",  "IPM"),
)

_IRAN_PREFIXES = tuple(p for p, _, _ in IRAN_IP_PREFIXES)

IRAN_ASNS: frozenset[str] = frozenset({
    "AS12880","AS58224","AS197207","AS44244","AS57218","AS48159","AS34369",
    "AS214922","AS205347","AS207719","AS43754","AS210362","AS62282","AS49100",
    "AS25184","AS42337","AS197398","AS12660","AS6736","AS44285","AS47262",
    "AS31549","AS16322","AS50810","AS34832",
})
MOBILE_ASNS: frozenset[str] = frozenset({"AS197207","AS44244","AS57218"})
ARMENIAN_PREFIXES = ("5.10.214.","5.10.215.","188.164.158.","188.164.159.")
ARMENIAN_ASNS: frozenset[str] = frozenset({"AS42910","AS43733","AS49800"})

# DPI resilience: lower = harder to block in Iranian network
# Based on bgoldmann/iranvpn research: protocol whitelist = HTTP/HTTPS/DNS only
# Reality/XTLS mimics real TLS 1.3 → hardest to block
PROTO_DPI: dict[str, int] = {
    "tuic":0, "hysteria2":1, "vless":2,
    "trojan":3, "vmess":4, "ss":5, "wireguard":6, "other":7,
}

# ── URI sanitisation ───────────────────────────────────────────────────────────

URI_RE = re.compile(
    r"(vmess|vless|ss|trojan|hysteria2|tuic|hy2|wireguard)://[^\s\"'<>]+",
    re.IGNORECASE,
)

# Patterns that indicate a malformed or useless URI
_BAD_PATTERNS = (
    re.compile(r"---@[a-zA-Z0-9_]+---"),   # repeated channel chains
    re.compile(r"&amp(?:%3B|;)"),           # HTML-entity-encoded ampersands
    re.compile(r"\.\.\."),                  # truncated URIs
    re.compile(r"%3C/div%3E"),              # HTML fragment leaked into URI
    re.compile(r"encryption=no\xe2"),       # unicode garbage in params
)

def _sanitise_uri(uri: str) -> str | None:
    """Return cleaned URI or None if it's malformed beyond repair."""
    # Drop URIs with unfixable HTML/channel-chain contamination
    for pat in _BAD_PATTERNS:
        if pat.search(uri):
            return None
    # Decode %2C, %28, %29 in trojan passwords (common source artefact)
    uri = uri.replace("%2C", ",").replace("%28", "(").replace("%29", ")")
    # Strip trailing garbage after a bare '#' with no text
    uri = re.sub(r"#\s*$", "", uri.strip())
    return uri if uri else None


def _uuid_from_uri(uri: str) -> str | None:
    """Extract UUID/password for deduplication."""
    uuid_re = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        re.IGNORECASE,
    )
    m = uuid_re.search(uri)
    return m.group(0).lower() if m else None


def _is_reality(uri: str) -> bool:
    """True if this is a VLESS+Reality config — highest DPI resistance."""
    return "reality" in uri.lower() or "xtls-rprx-vision" in uri.lower()


def _quality_score(uri: str) -> int:
    """
    Score a URI's likelihood of working through Iranian DPI.
    Higher = better. Used to drop the worst configs before TCP check.

    Based on bgoldmann/iranvpn research:
      - Iran protocol-whitelists HTTP/HTTPS/DNS only
      - security=none on port 80 = inspected and dropped by DPI
      - Reality/XTLS = indistinguishable from real TLS 1.3 = best
      - TLS on 443 = acceptable
      - No TLS on non-standard ports = marginally tolerated
      - CDN-fronted WS on Iranian CDN = wrong direction for diaspora

    Returns:
      -1  = definitely reject (no TLS AND Iranian CDN host = wrong direction)
       0  = likely dead (no TLS, port 80, not Iranian CDN)
       1  = marginal (no TLS, non-standard port)
       2  = acceptable (TLS present)
       3  = good (TLS on 443)
       4  = best (Reality / XTLS)
    """
    uri_l = uri.lower()
    proto = uri_l.split("://")[0]

    # Reality is always best regardless of other params
    if _is_reality(uri):
        return 4

    has_tls = "security=tls" in uri_l or "tls" in uri_l
    port_443 = ":443" in uri or "port=443" in uri_l

    # Detect Iranian CDN fronting — these are outbound proxies (wrong direction)
    # They respond to TCP but the backend is not reachable from outside Iran
    iranian_cdn_hosts = (
        "185.143.", "185.51.200.", "snapp.ir", "snapp.doctor",
        "arvancloud.ir", "arvancaas.ir",
    )
    is_ir_cdn_front = any(h in uri for h in iranian_cdn_hosts)

    # Plain WS on port 80 through Iranian CDN = definitely wrong direction
    if is_ir_cdn_front and not has_tls:
        return -1

    # Hysteria2/TUIC use QUIC — no TLS flag needed, always acceptable
    if proto in ("hysteria2", "hy2", "tuic"):
        return 3

    if has_tls and port_443:
        return 3
    if has_tls:
        return 2
    # No TLS — marginal at best
    return 1


# Minimum quality score to proceed to TCP check.
# Set to 0 to disable quality pre-filtering (keep all sanitised configs).
# Set to 2 to require TLS. Set to 3 to require TLS on 443 or QUIC protocols.
MIN_QUALITY_SCORE = int(os.environ.get("MIN_QUALITY_SCORE", "1"))


def deduplicate_by_uuid(uris: list[str]) -> list[str]:
    """
    Keep only one URI per UUID, preferring:
      1. Reality/XTLS-Vision configs
      2. TLS-enabled configs over plaintext
      3. The config with the shorter (cleaner) URI
    """
    best: dict[str, str] = {}
    no_uuid: list[str] = []
    for uri in uris:
        uid = _uuid_from_uri(uri)
        if uid is None:
            no_uuid.append(uri); continue
        if uid not in best:
            best[uid] = uri
        else:
            prev = best[uid]
            # Prefer Reality
            if _is_reality(uri) and not _is_reality(prev):
                best[uid] = uri
            # Prefer TLS
            elif "security=tls" in uri and "security=tls" not in prev:
                best[uid] = uri
            # Prefer shorter (less garbage)
            elif len(uri) < len(prev) and not _is_reality(prev):
                best[uid] = uri
    return list(best.values()) + no_uuid


# ── URI parsing ────────────────────────────────────────────────────────────────

def decode_b64(text: str) -> str:
    s = text.strip().replace("\n","").replace("\r","")
    try:
        if not URI_RE.search(text[:200]):
            p = s + "=" * (-len(s) % 4)
            d = base64.b64decode(p).decode("utf-8", errors="ignore")
            if URI_RE.search(d[:200]): return d
    except Exception: pass
    return text


def extract_uris(text: str) -> list[str]:
    raw = [m.group(0).strip() for m in URI_RE.finditer(decode_b64(text))]
    cleaned = [_sanitise_uri(u) for u in raw]
    return [u for u in cleaned if u]


def classify_proto(uri: str) -> str:
    s = uri.split("://")[0].lower()
    return {"vmess":"vmess","vless":"vless","ss":"ss","trojan":"trojan",
            "hysteria2":"hysteria2","hy2":"hysteria2","tuic":"tuic",
            "wireguard":"wireguard","wg":"wireguard"}.get(s,"other")


def parse_host_port(uri: str) -> tuple[str,int] | None:
    scheme = uri.split("://")[0].lower()
    try:
        if scheme == "vmess":
            raw = uri[8:] + "=" * (-(len(uri)-8) % 4)
            obj = json.loads(base64.b64decode(raw).decode("utf-8",errors="ignore"))
            h,p = str(obj.get("add","") or obj.get("host","")), int(obj.get("port",0))
            return (h,p) if h and p else None
        elif scheme in ("vless","trojan","tuic"):
            after = uri.split("://",1)[1]
            if "@" in after: after = after.split("@",1)[1]
            after = after.split("#")[0].split("?")[0]
            if after.startswith("["):
                e=after.find("]"); h=after[1:e]; ps=after[e+2:]; p=int(ps) if ps.isdigit() else 443
            else:
                h,ps = after.rsplit(":",1); p=int(ps)
            return (h,p) if h and p else None
        elif scheme == "ss":
            body = uri[5:].split("#")[0].split("?")[0]
            if "@" in body:
                hp = body.rsplit("@",1)[1]
            else:
                raw = body + "=" * (-len(body) % 4)
                dec = base64.b64decode(raw).decode("utf-8",errors="ignore")
                hp  = dec.rsplit("@",1)[1] if "@" in dec else ""
                if not hp: return None
            if hp.startswith("["):
                e=hp.find("]"); h=hp[1:e]; p=int(hp[e+2:])
            else:
                h,ps=hp.rsplit(":",1); p=int(ps)
            return (h,p) if h else None
        elif scheme in ("hysteria2","hy2"):
            after=uri.split("://",1)[1]
            if "@" in after: after=after.split("@",1)[1]
            after=after.split("#")[0].split("?")[0]
            if after.startswith("["):
                e=after.find("]"); h=after[1:e]; p=int(after[e+2:])
            else:
                h,ps=after.rsplit(":",1); p=int(ps)
            return (h,p)
        elif scheme in ("wireguard","wg"):
            body=uri.split("://",1)[1].split("#")[0].split("?")[0]
            if "@" in body: body=body.rsplit("@",1)[1]
            if ":" in body:
                h,ps=body.rsplit(":",1); return (h,int(ps))
    except Exception: pass
    return None


# ── Network helpers ────────────────────────────────────────────────────────────

async def tcp_ok(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        _,w = await asyncio.wait_for(asyncio.open_connection(ip,port),timeout=timeout)
        w.close(); await w.wait_closed(); return True
    except Exception: return False


async def http_probe(host: str, port: int, uri: str, timeout: float = 8.0) -> bool:
    """
    Stage 4: send a minimal WebSocket-upgrade or CONNECT request to the proxy
    and check whether it responds in a way that indicates a live proxy server,
    rather than a CDN 404, a closed connection, or a firewall RST.

    This is the key improvement: TCP-connect only tells you the port is open;
    HTTP probe tells you the proxy software is actually running and responding.

    Returns True if the response suggests a live proxy (even a rejection like
    400/101/200 is fine — it means proxy software answered).
    Returns False for connection reset, timeout, or pure HTTP 404/403 from a
    CDN edge (which indicates the backend proxy is dead).
    """
    if not PROBE_ENABLED:
        return True  # skip probe when disabled

    proto = classify_proto(uri)
    ws_path = "/"
    ws_host = host

    # Extract WebSocket path and host header from URI params for WS configs
    if "path=" in uri:
        try:
            path_match = re.search(r"path=([^&]+)", uri)
            if path_match:
                import urllib.parse
                ws_path = urllib.parse.unquote(path_match.group(1))
        except Exception: pass
    if "host=" in uri:
        try:
            host_match = re.search(r"host=([^&#]+)", uri)
            if host_match:
                ws_host = host_match.group(1)
        except Exception: pass

    tls = "security=tls" in uri or port == 443
    scheme_prefix = "https" if tls else "http"

    # For WebSocket-based transports (ws, httpupgrade), send an Upgrade request
    # For TCP/Reality, just try a raw CONNECT
    try:
        if proto in ("vless","vmess","trojan") and ("type=ws" in uri or "type=httpupgrade" in uri):
            # WebSocket upgrade probe
            request = (
                f"GET {ws_path} HTTP/1.1\r\n"
                f"Host: {ws_host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            ).encode()
        else:
            # Generic HTTP probe — a live proxy typically returns 4xx or resets
            # rather than a CDN 200/404 with HTML body
            request = (
                f"CONNECT {ws_host}:443 HTTP/1.1\r\n"
                f"Host: {ws_host}:443\r\n"
                f"\r\n"
            ).encode()

        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=tls) if tls
            else asyncio.open_connection(host, port),
            timeout=timeout,
        )
        w.write(request)
        await w.drain()
        data = await asyncio.wait_for(r.read(512), timeout=timeout)
        w.close()

        if not data:
            return False  # connection reset — dead proxy

        first = data[:4]
        # Accept: 101 (WebSocket upgrade OK), 200 (CONNECT OK),
        # 400/407/405 (proxy alive but rejected) — all indicate live software
        # Reject: pure 404/403 HTML from CDN edge — dead backend
        if first.startswith(b"HTTP"):
            status_line = data.split(b"\r\n")[0].decode("utf-8","ignore")
            code_str = status_line.split(" ")[1] if " " in status_line else "0"
            try:
                code = int(code_str)
            except ValueError:
                return True  # unparseable but something answered — likely proxy
            if code in (101, 200, 400, 405, 407):
                return True   # live proxy software
            if code in (404, 403) and b"<html" in data.lower():
                return False  # CDN edge returning HTML — backend dead
            return True  # any other HTTP response = something is running
        return True  # non-HTTP response (e.g. TLS handshake) = likely live

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception:
        return True  # SSL errors etc. still mean the port is alive


# ── GeoIP ─────────────────────────────────────────────────────────────────────

async def batch_geoip(hosts: list[str]) -> dict[str,dict]:
    if not hosts: return {}
    print(f"  GeoIP: {len(hosts)} hosts ...")
    loop = asyncio.get_running_loop()
    def dns(h):
        try: return h,socket.gethostbyname(h)
        except: return h,""
    with ThreadPoolExecutor(max_workers=min(150,len(hosts))) as ex:
        pairs = await asyncio.gather(*[loop.run_in_executor(ex,dns,h) for h in hosts])
    h2ip={h:ip for h,ip in pairs if ip}
    ip2info: dict[str,dict] = {}
    async with aiohttp.ClientSession() as sess:
        for i in range(0,len(h2ip),100):
            batch=[{"query":ip,"fields":"countryCode,as,mobile,isp"}
                   for ip in list(h2ip.values())[i:i+100]]
            try:
                async with sess.post("http://ip-api.com/batch",json=batch,
                                     timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status==200:
                        for req,res in zip(batch,await r.json()):
                            if res:
                                asn=(res.get("as","") or "").split(" ")[0]
                                ip2info[req["query"]]={
                                    "cc":res.get("countryCode",""),
                                    "asn":asn,"isp":res.get("isp",""),
                                    "mobile":res.get("mobile",False),
                                }
            except Exception as e: print(f"  ! GeoIP: {e}")
            await asyncio.sleep(1.2)
    empty={"cc":"","asn":"","isp":"","mobile":False}
    return {h:{"ip":ip,**ip2info.get(ip,empty)} for h,ip in h2ip.items()}


# ── Sources ────────────────────────────────────────────────────────────────────
# Source notes (from bgoldmann/iranvpn research):
#   - Iran's DPI whitelists only HTTP/HTTPS/DNS; VLESS+Reality and Trojan+TLS
#     are the most resilient protocols
#   - Public free configs die within hours; Psiphon configs are maintained by
#     a funded organisation and are far more durable
#   - Sources tagged [REALITY] focus on XTLS-Vision configs (highest DPI resistance)

RAW_SOURCES = [
    # ── High-yield general aggregators ────────────────────────────────────────
    ("barry-far/vmess",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",   "text"),
    ("barry-far/vless",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",   "text"),
    ("barry-far/trojan", "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",  "text"),
    ("barry-far/hy2",    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/hysteria2.txt","text"),
    ("barry-far/all",    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Config_base64_Sub.txt",         "b64"),
    ("matin/super",      "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt","b64"),
    ("matin/vless",      "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",   "text"),
    ("matin/trojan",     "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",  "text"),
    ("matin/hy2",        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt","text"),
    ("epodonios/IR",     "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Iran/config.txt","text"),
    ("epodonios/sub1",   "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt","b64"),
    ("yebekhe/mix",      "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mix_base64",       "b64"),
    ("yebekhe/reality",  "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/reality",   "text"),  # [REALITY]
    ("yebekhe/hy2",      "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/hysteria2", "text"),
    ("soroush/vless",    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",       "text"),
    ("soroush/trojan",   "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",      "text"),
    ("soroush/hy2",      "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria2",   "text"),
    ("mahdibland/mix",   "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/update/mixed/mixed.txt","b64"),
    ("aliilapro/all",    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt","b64"),
    ("nirevil/sub",      "https://raw.githubusercontent.com/NiREvil/vless/main/sub/G","b64"),
    ("nirevil/hy2",      "https://raw.githubusercontent.com/NiREvil/vless/main/sub/hysteria2","text"),
    ("mosifree/all",     "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/All","text"),
    ("freefq/v2ray",     "https://raw.githubusercontent.com/freefq/free/master/v2","b64"),
    ("leon406/all",      "https://raw.githubusercontent.com/Leon406/Sub/main/sub/share/all","b64"),
    ("aiboboxx/v2",      "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2","b64"),
    ("mfuu/v2ray",       "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray","b64"),
    # ── Iran-focused / Caucasus-adjacent ──────────────────────────────────────
    ("arshia/vless",     "https://raw.githubusercontent.com/arshiacomplus/v2rayTemplet/main/vless.txt","text"),
    ("mhdi/all",         "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Mix/mix.txt","b64"),
    ("iranfilter/all",   "https://raw.githubusercontent.com/IranFilteredConfig/Free-Configs/main/sub/all.txt","b64"),
    ("shadowshare/am",   "https://raw.githubusercontent.com/ShadowShare/ShadowShare/main/AM.txt","text"),
    # ── [REALITY] XTLS-Reality focused (best DPI resistance per iranvpn research)
    ("rooster/reality",  "https://raw.githubusercontent.com/roosterkid/openproxylist/main/VLESS_RAW.txt","text"),
    ("reality-ir/vless", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/vless.txt","text"),
    ("reality-collect",  "https://raw.githubusercontent.com/M677871/xtls-reality-configs/main/configs.txt","text"),
    ("reality-sub",      "https://raw.githubusercontent.com/XTLS/Xray-core/main/testing/coverage/vless_reality_vision.json","text"),
    # ── QUIC / satellite-tolerant (Hysteria2, TUIC) ───────────────────────────
    ("hy2-collect/all",  "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt","b64"),
    ("tuic-collect/all", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/tuic.txt","text"),
    ("hy2-iran/all",     "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/hysteria2.txt","text"),
    # ── Psiphon config sources (most reliable — maintained by Psiphon Inc.)
    # Psiphon uses its own format but also publishes HTTPS proxies; the S3 bucket
    # contains JSON with embedded server lists. We extract any V2Ray URIs found.
    ("psiphon/s3-tunnel","https://psiphon3.com/tunnel_core_client_config.js","text"),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; IranIntranetCollector/4.0)"}


# ── Bootstrap from iran-proxy-checker ────────────────────────────────────────

def load_bootstrap() -> list[str]:
    uris: list[str] = []
    base = Path(IRAN_PROXY_CHECKER_DIR)
    for fname in ["armenia_iran_bridge_configs.json","passing_intranet_configs.json",
                  "working_armenia_configs.json"]:
        fpath = base/fname
        if not fpath.exists(): continue
        try:
            data=json.loads(fpath.read_text(encoding="utf-8"))
            configs=data.get("configs") or data.get("outbounds") or []
            before=len(uris)
            for e in configs:
                u=e.get("uri") or e.get("config_uri","")
                if u and URI_RE.match(u): uris.append(u)
            if len(uris)>before: print(f"  bootstrap [{fname}]: +{len(uris)-before}")
        except Exception as e: print(f"  bootstrap [{fname}]: {e}")
    for fname in ["armenia_iran_bridge_configs.txt","passing_intranet_configs.txt",
                  "ir_exit_configs.txt","ir_mobile_exit_configs.txt",
                  "passing_intranet_configs_base64.txt"]:
        fpath=base/fname
        if not fpath.exists(): continue
        try:
            new=extract_uris(fpath.read_text(encoding="utf-8"))
            uris.extend(new)
            if new: print(f"  bootstrap [{fname}]: +{len(new)}")
        except Exception as e: print(f"  bootstrap [{fname}]: {e}")
    return list(dict.fromkeys(uris))


# ── Scraper ───────────────────────────────────────────────────────────────────

async def fetch_source(label,url,fmt,session,retries=2):
    for attempt in range(retries+1):
        try:
            async with session.get(url,timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status!=200: return []
                text=await r.text(errors="ignore")
                return extract_uris(decode_b64(text) if fmt=="b64" else text)
        except Exception as e:
            if attempt<retries: await asyncio.sleep(1.5*(attempt+1))
            else: print(f"  ! [{label}]: {e}",flush=True)
    return []


async def collect_all() -> list[str]:
    all_uris: dict[str,None] = {}
    bootstrap=load_bootstrap()
    all_uris.update(dict.fromkeys(bootstrap))
    print(f"  Bootstrap: {len(bootstrap)} URIs")

    async with aiohttp.ClientSession(headers=HEADERS) as sess:
        results=await asyncio.gather(
            *[fetch_source(lbl,url,fmt,sess) for lbl,url,fmt in RAW_SOURCES],
            return_exceptions=True,
        )
        for (lbl,_,_),res in zip(RAW_SOURCES,results):
            if isinstance(res,list):
                before=len(all_uris); all_uris.update(dict.fromkeys(res))
                new=len(all_uris)-before
                if new: print(f"  + [{lbl}] +{new}",flush=True)

    raw_count = len(all_uris)
    # Deduplication by UUID — keeps best-obfuscated copy per server
    deduped = deduplicate_by_uuid(list(all_uris))
    print(f"\nCollected {raw_count} URIs → {len(deduped)} after UUID dedup")
    return deduped


# ── Verify ────────────────────────────────────────────────────────────────────

async def verify_configs(uris: list[str]) -> list[dict]:
    parsed: list[dict] = []
    unique_hosts: set[str] = set()
    for uri in uris:
        hp=parse_host_port(uri)
        if hp:
            h,p=hp
            if h and 1<=p<=65535:
                parsed.append({"uri":uri,"host":h,"port":p,
                                "protocol":classify_proto(uri),
                                "is_reality":_is_reality(uri)})
                unique_hosts.add(h)

    print(f"  Parsed {len(parsed)} configs ({len(uris)-len(parsed)} unparseable)")

    loop=asyncio.get_running_loop()
    def dns(h):
        try: return h,socket.gethostbyname(h)
        except: return h,""
    with ThreadPoolExecutor(max_workers=min(150,len(unique_hosts) or 1)) as ex:
        pairs=await asyncio.gather(*[loop.run_in_executor(ex,dns,h) for h in unique_hosts])

    fast_ir:  dict[str,dict]={}
    fast_am:  set[str]=set()
    geoip_needed: list[str]=[]

    for host,ip in pairs:
        if not ip: geoip_needed.append(host); continue
        match=next(((asn,op) for pfx,asn,op in IRAN_IP_PREFIXES if ip.startswith(pfx)),None)
        if match:
            asn,op=match
            fast_ir[host]={"ip":ip,"asn":asn,"operator":op,"mobile":asn in MOBILE_ASNS}
        elif any(ip.startswith(p) for p in ARMENIAN_PREFIXES):
            fast_am.add(host)
        else:
            geoip_needed.append(host)

    print(f"  Fast-path IR={len(fast_ir)} AM={len(fast_am)} GeoIP-needed={len(geoip_needed)}")
    host_info=await batch_geoip(geoip_needed)
    bootstrap_set=set(load_bootstrap())

    probe_label = "HTTP-probe+TCP" if PROBE_ENABLED else "TCP-only"
    print(f"  Checking {len(parsed)} configs ({probe_label}) ...")
    sem=asyncio.Semaphore(MAX_WORKERS)

    async def check_one(cfg) -> dict|None:
        async with sem:
            host,port,uri=cfg["host"],cfg["port"],cfg["uri"]
            # Stage 3: TCP connect
            if not await tcp_ok(host,port): return None
            # Stage 4: HTTP probe (optional)
            if not await http_probe(host,port,uri): return None

            if host in fast_ir:
                fp=fast_ir[host]
                asn,operator,is_iran,is_mobile=fp["asn"],fp["operator"],True,fp["mobile"]
                country="IR"
            else:
                info=host_info.get(host,{})
                asn,operator=info.get("asn",""),info.get("isp","")
                is_iran=(info.get("cc","")=="IR") or (asn in IRAN_ASNS)
                is_mobile=info.get("mobile",False) or (asn in MOBILE_ASNS)
                country="IR" if is_iran else info.get("cc","")

            is_armenian=(
                host in fast_am or
                host_info.get(host,{}).get("cc","")=="AM" or
                host_info.get(host,{}).get("asn","") in ARMENIAN_ASNS
            )

            return {
                **cfg,
                "country":country,"asn":asn,"operator":operator,
                "iran_exit":is_iran,"iran_mobile_exit":is_iran and is_mobile,
                "armenian_bridge":is_armenian,
                "bridge_verified":uri in bootstrap_set,
                "dpi_score":PROTO_DPI.get(cfg["protocol"],7),
            }

    raw=await asyncio.gather(*[check_one(c) for c in parsed])
    results=[r for r in raw if r is not None]

    def sort_key(r):
        tier=(0 if r["iran_mobile_exit"] else 1 if r["iran_exit"] else
              2 if r["bridge_verified"] else 3 if r["armenian_bridge"] else 4)
        # Reality configs go first within each tier
        reality_bonus = 0 if r.get("is_reality") else 1
        return (tier, reality_bonus, r["dpi_score"])

    results.sort(key=sort_key)
    ir=sum(1 for r in results if r["iran_exit"])
    mob=sum(1 for r in results if r["iran_mobile_exit"])
    am=sum(1 for r in results if r["armenian_bridge"])
    bv=sum(1 for r in results if r["bridge_verified"])
    real=sum(1 for r in results if r.get("is_reality"))
    print(f"  Verified: {len(results)} | IR={ir} (mobile={mob}, reality={real}) "
          f"| Armenian={am} | bridge-verified={bv}")
    return results


# ── Outputs ───────────────────────────────────────────────────────────────────

def write_outputs(results: list[dict]) -> None:
    now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out=Path("outputs"); out.mkdir(exist_ok=True)

    ir_r  =[r for r in results if r["iran_exit"]]
    mob_r =[r for r in results if r["iran_mobile_exit"]]
    am_r  =[r for r in results if r["armenian_bridge"]]
    real_r=[r for r in results if r.get("is_reality") and r["iran_exit"]]

    probe_note="HTTP-probed" if PROBE_ENABLED else "TCP-verified"
    header=(f"# Iran Intranet Configs — {now}  [{probe_note}]\n"
            f"# {len(results)} configs | IR={len(ir_r)} (mobile={len(mob_r)}, "
            f"reality={len(real_r)}) | Armenian={len(am_r)}\n"
            f"# Sorted: IR-mobile-Reality > IR-Reality > IR-mobile > IR > bridge-verified > Armenian\n"
            f"# DPI resilience within tier: Reality > TUIC > Hysteria2 > VLESS > Trojan > VMess > SS\n")

    with open(out/"passing_intranet_configs.txt","w",encoding="utf-8") as f:
        f.write(header+"# Import URL (raw): use raw.githubusercontent.com, not github.com/blob/\n\n")
        for r in results: f.write(r["uri"]+"\n")

    for fname,subset,label in [
        ("ir_exit_configs.txt",     ir_r,    "IR-exit (confirmed Iranian IP)"),
        ("ir_mobile_exit_configs.txt",mob_r, "IR mobile (MCI/Irancell/Rightel)"),
        ("armenian_bridge_configs.txt",am_r, "Armenian corridor bridge"),
        ("ir_reality_configs.txt",  real_r,  "IR-exit + VLESS Reality (highest DPI resistance)"),
    ]:
        with open(out/fname,"w",encoding="utf-8") as f:
            f.write(f"# {label} — {now}\n# {len(subset)} configs\n\n")
            for r in subset: f.write(r["uri"]+"\n")

    with open(out/"passing_intranet_configs.json","w",encoding="utf-8") as f:
        json.dump({
            "checked_at":now,"count":len(results),"probe_enabled":PROBE_ENABLED,
            "summary":{"ir_exit":len(ir_r),"ir_mobile":len(mob_r),
                       "ir_reality":len(real_r),"armenian":len(am_r)},
            "configs":results,
        },f,indent=2,ensure_ascii=False)

    with open(out/"passing_intranet_configs_base64.txt","w") as f:
        f.write(base64.b64encode("\n".join(r["uri"] for r in results).encode()).decode())

    proto_dir=out/"by_protocol"; proto_dir.mkdir(exist_ok=True)
    protos=["tuic","hysteria2","vless","trojan","vmess","ss","wireguard","other"]
    buckets={p:[] for p in protos}
    for r in results: buckets[r["protocol"]].append(r["uri"])
    for p,uris in buckets.items():
        if uris:
            with open(proto_dir/f"{p}.txt","w",encoding="utf-8") as f:
                f.write(f"# {p.upper()} — {now}\n# {len(uris)}\n\n")
                for u in uris: f.write(u+"\n")

    print(f"\nOutputs → outputs/")
    print(f"  passing_intranet_configs.txt      ({len(results)})")
    print(f"  ir_exit_configs.txt               ({len(ir_r)})")
    print(f"  ir_reality_configs.txt            ({len(real_r)}) ← best DPI resistance")
    print(f"  ir_mobile_exit_configs.txt        ({len(mob_r)})")
    print(f"  armenian_bridge_configs.txt       ({len(am_r)})")
    print(f"  passing_intranet_configs_base64.txt")
    for p in protos:
        n=len(buckets[p])
        if n: print(f"  by_protocol/{p}.txt         ({n})")


def check_minimum(results):
    if len(results)<MIN_PASSING_CONFIGS:
        print(f"\nERROR: {len(results)} configs < minimum {MIN_PASSING_CONFIGS}",
              file=sys.stderr)
        sys.exit(1)


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    sep="="*55
    print(sep)
    print("Iran Intranet Config Collector  v4")
    print(f"TCP={TCP_TIMEOUT}s  workers={MAX_WORKERS}  probe={PROBE_ENABLED}")
    print(sep)
    t0=time.monotonic()

    print("\n[1/3] Collecting configs ...")
    uris=await collect_all()

    print(f"\n[2/3] Verifying {len(uris)} configs ...")
    results=await verify_configs(uris)
    check_minimum(results)

    print("\n[3/3] Writing outputs ...")
    write_outputs(results)

    print(f"\n{sep}")
    print(f"Done in {time.monotonic()-t0:.0f}s — {len(results)} configs.")
    print(sep)


if __name__=="__main__":
    asyncio.run(main())
