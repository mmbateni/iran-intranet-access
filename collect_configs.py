#!/usr/bin/env python3
"""
Iran Intranet Config Collector & Verifier
==========================================
Direction A — Diaspora/Researchers → SHOMA

Collects V2Ray / VLESS / Trojan / Shadowsocks / Hysteria2 / TUIC configs
from 50+ public aggregators and verifies which ones can reach the Iranian
national intranet (SHOMA / NIN) — resources only accessible from within
Iranian IP space: government services, banking, universities, archives.

Why this is needed
------------------
Iran's National Information Network (SHOMA) is only reachable from Iranian
AS space. The Iranian diaspora, researchers, and journalists outside Iran
cannot access these resources without a proxy that exits inside Iran.

Network context (2026)
-----------------------
TCI (AS12880/AS58224), MCI/Hamrahe Aval (AS197207), and Irancell (AS44244)
control ~80% of routable prefixes. All gateways pass through TIC (AS48159).
During the Jan 2026 shutdown, TCI lost 810 prefixes. Mobile carriers
survived longest: MCI kept 689 routes, Irancell kept 368.

Verification
------------
A config passes if its host resolves to an Iranian or Armenian AS (GeoIP
+ ASN), or matches a known Iranian IP prefix (fast-path, no API call),
AND the proxy server accepts TCP connections within TCP_TIMEOUT seconds.

Outputs  (all in outputs/)
--------------------------
  passing_intranet_configs.txt        subscription-ready (bare URIs)
  passing_intranet_configs.json       structured with metadata
  passing_intranet_configs_base64.txt base64 subscription blob
  ir_exit_configs.txt                 IR-exit only
  ir_mobile_exit_configs.txt          MCI/Irancell/Rightel (shutdown-resilient)
  armenian_bridge_configs.txt         Armenian corridor
  by_protocol/                        per-protocol splits
"""

import asyncio
import base64
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
TCP_TIMEOUT            = float(os.environ.get("TCP_TIMEOUT",         "3.0"))
HTTP_TIMEOUT           = int(  os.environ.get("HTTP_TIMEOUT",        "10"))
MAX_WORKERS            = int(  os.environ.get("MAX_WORKERS",         "80"))
SKIP_V2RAY_TEST        = os.environ.get("SKIP_V2RAY_TEST",    "1").strip() == "1"
MIN_PASSING_CONFIGS    = int(  os.environ.get("MIN_PASSING_CONFIGS", "100"))

# ── Iranian IP prefix registry ─────────────────────────────────────────────────
# Format: (prefix, ASN, operator, network_type)
# Sources: RIPE NCC, bgp.he.net/country/IR, confirmed VPN exit observations.
# Mobile operators flagged — they retain routes longest during shutdowns.

IRAN_IP_PREFIXES: tuple[tuple[str, str, str, str], ...] = (
    # TCI / Data Communications Company (AS12880) — backbone, first to disappear
    ("2.176.",    "AS12880",  "TCI",              "backbone"),
    ("2.177.",    "AS12880",  "TCI",              "backbone"),
    ("2.178.",    "AS12880",  "TCI",              "backbone"),
    ("2.179.",    "AS12880",  "TCI",              "backbone"),
    ("2.180.",    "AS12880",  "TCI",              "backbone"),
    ("2.181.",    "AS12880",  "TCI",              "backbone"),
    ("2.182.",    "AS12880",  "TCI",              "backbone"),
    ("2.183.",    "AS12880",  "TCI",              "backbone"),
    ("2.184.",    "AS12880",  "TCI",              "backbone"),
    ("2.185.",    "AS12880",  "TCI",              "backbone"),
    ("2.186.",    "AS12880",  "TCI",              "backbone"),
    ("2.187.",    "AS12880",  "TCI",              "backbone"),
    ("2.188.",    "AS12880",  "TCI",              "backbone"),
    ("2.189.",    "AS12880",  "TCI",              "backbone"),
    ("2.190.",    "AS12880",  "TCI",              "backbone"),
    ("2.191.",    "AS12880",  "TCI",              "backbone"),
    ("5.160.",    "AS12880",  "TCI",              "backbone"),
    ("5.164.",    "AS12880",  "TCI",              "backbone"),
    ("5.168.",    "AS12880",  "TCI",              "backbone"),
    ("5.172.",    "AS12880",  "TCI",              "backbone"),
    ("5.176.",    "AS12880",  "TCI",              "backbone"),
    ("5.180.",    "AS12880",  "TCI",              "backbone"),
    ("5.184.",    "AS12880",  "TCI",              "backbone"),
    ("5.188.",    "AS12880",  "TCI",              "backbone"),
    ("5.192.",    "AS12880",  "TCI",              "backbone"),
    ("5.196.",    "AS12880",  "TCI",              "backbone"),
    ("5.200.",    "AS12880",  "TCI",              "backbone"),
    ("78.38.",    "AS12880",  "TCI",              "backbone"),
    ("78.39.",    "AS12880",  "TCI",              "backbone"),
    # TCI parent (AS58224)
    ("217.218.",  "AS58224",  "TCI",              "backbone"),
    ("217.219.",  "AS58224",  "TCI",              "backbone"),
    ("46.100.",   "AS58224",  "TCI",              "backbone"),
    ("46.101.",   "AS58224",  "TCI",              "backbone"),
    # MCI / Hamrahe Aval (AS197207) — 66% market; 689 routes survived Jan 2026
    ("89.32.",    "AS197207", "MCI",              "mobile"),
    ("89.33.",    "AS197207", "MCI",              "mobile"),
    ("89.34.",    "AS197207", "MCI",              "mobile"),
    ("89.35.",    "AS197207", "MCI",              "mobile"),
    ("151.232.",  "AS197207", "MCI",              "mobile"),
    ("151.233.",  "AS197207", "MCI",              "mobile"),
    ("151.234.",  "AS197207", "MCI",              "mobile"),
    ("151.235.",  "AS197207", "MCI",              "mobile"),
    # Irancell (AS44244) — 10% market; 368 routes survived Jan 2026
    ("91.92.",    "AS44244",  "Irancell",         "mobile"),
    ("91.93.",    "AS44244",  "Irancell",         "mobile"),
    ("91.94.",    "AS44244",  "Irancell",         "mobile"),
    ("91.95.",    "AS44244",  "Irancell",         "mobile"),
    ("185.112.",  "AS44244",  "Irancell",         "mobile"),
    # Rightel / Tamin Telecom (AS57218)
    ("91.186.",   "AS57218",  "Rightel",          "mobile"),
    ("91.187.",   "AS57218",  "Rightel",          "mobile"),
    # Shatel / TIC (AS48159)
    ("185.141.",  "AS48159",  "Shatel",           "isp"),
    ("109.122.",  "AS48159",  "Shatel",           "isp"),
    # Soroush Rasaneh (AS214922) — confirmed IR-exit 2026-03-29
    ("81.12.",    "AS214922", "Soroush-Rasaneh",  "isp"),
    ("81.13.",    "AS214922", "Soroush-Rasaneh",  "isp"),
    ("81.14.",    "AS214922", "Soroush-Rasaneh",  "isp"),
    ("81.15.",    "AS214922", "Soroush-Rasaneh",  "isp"),
    # Arvan Cloud CDN (AS205347, AS207719) — gov/banking domain fronting
    ("185.51.200.", "AS205347", "Arvan-Cloud",    "cdn"),
    ("185.143.",  "AS207719", "Arvan-Cloud",      "cdn"),
    ("194.36.170.", "AS207719","Arvan-Cloud",     "cdn"),
    # Asiatech (AS43754, AS210362)
    ("194.5.175.","AS210362", "Asiatech",         "isp"),
    ("195.146.",  "AS43754",  "Asiatech",         "isp"),
    # Fanap / Pasargad Bank (AS62282)
    ("91.108.4.", "AS62282",  "Fanap",            "isp"),
    ("91.108.8.", "AS62282",  "Fanap",            "isp"),
    # Pars Online, Afranet, Respina, HiWeb
    ("213.176.",  "AS49100",  "ParsOnline",       "isp"),
    ("62.193.",   "AS25184",  "Afranet",          "isp"),
    ("185.167.",  "AS42337",  "Respina",          "isp"),
    ("94.182.",   "AS197398", "HiWeb",            "isp"),
    ("94.183.",   "AS197398", "HiWeb",            "isp"),
    # IPM Research Network
    ("212.16.",   "AS12660",  "IPM",              "academic"),
)

_IRAN_PREFIXES = tuple(p for p, _, _, _ in IRAN_IP_PREFIXES)

IRAN_ASNS: frozenset[str] = frozenset({
    "AS12880", "AS58224", "AS197207", "AS44244", "AS57218",
    "AS48159", "AS34369", "AS214922", "AS205347", "AS207719",
    "AS43754", "AS210362", "AS62282", "AS49100", "AS25184",
    "AS42337", "AS197398", "AS12660", "AS6736", "AS44285",
    "AS47262", "AS31549", "AS16322", "AS50810", "AS34832",
})

MOBILE_ASNS: frozenset[str] = frozenset({"AS197207", "AS44244", "AS57218"})

# Armenian corridor — South Caucasus bridge route into Iran
ARMENIAN_PREFIXES: tuple[str, ...] = (
    "5.10.214.", "5.10.215.",
    "188.164.158.", "188.164.159.",
    "37.252.0.", "37.252.1.",
)
ARMENIAN_ASNS: frozenset[str] = frozenset({"AS42910", "AS43733", "AS49800"})

# DPI resilience order — within each tier, prefer harder-to-block protocols
# per the Iranian DPI environment (HTTP/3 throttled on Irancell since late 2025)
PROTO_ORDER: dict[str, int] = {
    "tuic": 0, "hysteria2": 1, "vless": 2,
    "trojan": 3, "vmess": 4, "ss": 5, "wireguard": 6, "other": 7,
}


def get_ir_operator(ip: str) -> tuple[str, str, str] | None:
    for prefix, asn, operator, net_type in IRAN_IP_PREFIXES:
        if ip.startswith(prefix):
            return asn, operator, net_type
    return None


# ── Sources ────────────────────────────────────────────────────────────────────

RAW_SOURCES = [
    # barry-far (updates every 15 min, one of the largest)
    ("barry-far/vmess",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",    "text"),
    ("barry-far/vless",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",    "text"),
    ("barry-far/ss",      "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",       "text"),
    ("barry-far/trojan",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",   "text"),
    ("barry-far/hy2",     "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/hysteria2.txt","text"),
    ("barry-far/all",     "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Config_base64_Sub.txt",          "b64"),
    # MatinGhanbari
    ("matin/super",   "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt","b64"),
    ("matin/vless",   "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",   "text"),
    ("matin/trojan",  "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",  "text"),
    ("matin/hy2",     "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt","text"),
    # Epodonios — has Iran-specific subfolder
    ("epodonios/IR",   "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Iran/config.txt","text"),
    ("epodonios/sub1", "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt","b64"),
    ("epodonios/sub2", "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub2.txt","b64"),
    # yebekhe / TelegramV2rayCollector
    ("yebekhe/mix",     "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mix_base64",       "b64"),
    ("yebekhe/reality", "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/reality",   "text"),
    ("yebekhe/hy2",     "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/hysteria2", "text"),
    # soroushmirzaei
    ("soroush/vmess",  "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess",       "text"),
    ("soroush/vless",  "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",       "text"),
    ("soroush/trojan", "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",      "text"),
    ("soroush/ss",     "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/shadowsocks", "text"),
    ("soroush/hy2",    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria2",   "text"),
    # mahdibland
    ("mahdibland/mix", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/update/mixed/mixed.txt","b64"),
    # Other aggregators
    ("aliilapro/all",  "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",                                        "b64"),
    ("nirevil/sub",    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/G",                                                     "b64"),
    ("nirevil/hy2",    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/hysteria2",                                              "text"),
    ("mosifree/all",   "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/All",                                                "text"),
    ("freefq/v2ray",   "https://raw.githubusercontent.com/freefq/free/master/v2",                                                        "b64"),
    ("leon406/all",    "https://raw.githubusercontent.com/Leon406/Sub/main/sub/share/all",                                               "b64"),
    ("10ium/mix",      "https://raw.githubusercontent.com/10ium/V2Hub3/main/merged_base64",                                              "b64"),
    ("aiboboxx/v2",    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",                                                   "b64"),
    ("mfuu/v2ray",     "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",                                                     "b64"),
    # Iran-focused / Caucasus-adjacent sources
    ("arshia/vless",     "https://raw.githubusercontent.com/arshiacomplus/v2rayTemplet/main/vless.txt",                                  "text"),
    ("mhdi/all",         "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Mix/mix.txt",                         "b64"),
    ("iranfilter/all",   "https://raw.githubusercontent.com/IranFilteredConfig/Free-Configs/main/sub/all.txt",                          "b64"),
    ("shadowshare/am",   "https://raw.githubusercontent.com/ShadowShare/ShadowShare/main/AM.txt",                                        "text"),
    ("rooster/reality",  "https://raw.githubusercontent.com/roosterkid/openproxylist/main/VLESS_RAW.txt",                               "text"),
    # Satellite-tolerant protocols (QUIC-based — work over high-latency links)
    ("hy2-collect/all",  "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",                     "b64"),
    ("tuic-collect/all", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/tuic.txt",                                    "text"),
    ("hy2-iran/all",     "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/hysteria2.txt",                               "text"),
    ("reality-ir/all",   "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/vless.txt",                                   "text"),
]

URI_RE = re.compile(
    r"(vmess|vless|ss|trojan|hysteria2|tuic|hy2|wireguard)://[^\s\"'<>]+",
    re.IGNORECASE,
)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; IranIntranetCollector/3.0)"}

# ── URI helpers ────────────────────────────────────────────────────────────────

def decode_b64(text: str) -> str:
    stripped = text.strip().replace("\n","").replace("\r","")
    try:
        if not URI_RE.search(text[:200]):
            padded  = stripped + "=" * (-len(stripped) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if URI_RE.search(decoded[:200]):
                return decoded
    except Exception:
        pass
    return text


def extract_uris(text: str) -> list[str]:
    return [m.group(0).strip() for m in URI_RE.finditer(decode_b64(text))]


def classify_proto(uri: str) -> str:
    s = uri.split("://")[0].lower()
    return {"vmess":"vmess","vless":"vless","ss":"ss","trojan":"trojan",
            "hysteria2":"hysteria2","hy2":"hysteria2","tuic":"tuic",
            "wireguard":"wireguard","wg":"wireguard"}.get(s,"other")


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
                e = after.find("]"); h = after[1:e]
                ps = after[e+2:]; p = int(ps) if ps.isdigit() else 443
            else:
                h, ps = after.rsplit(":",1); p = int(ps)
            return (h, p) if h and p else None
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
                e = hp.find("]"); h = hp[1:e]; p = int(hp[e+2:])
            else:
                h, ps = hp.rsplit(":",1); p = int(ps)
            return (h, p) if h else None
        elif scheme in ("hysteria2","hy2"):
            after = uri.split("://",1)[1]
            if "@" in after: after = after.split("@",1)[1]
            after = after.split("#")[0].split("?")[0]
            if after.startswith("["):
                e = after.find("]"); h = after[1:e]; p = int(after[e+2:])
            else:
                h, ps = after.rsplit(":",1); p = int(ps)
            return (h, p)
        elif scheme in ("wireguard","wg"):
            body = uri.split("://",1)[1].split("#")[0].split("?")[0]
            if "@" in body: body = body.rsplit("@",1)[1]
            if ":" in body:
                h, ps = body.rsplit(":",1); return (h, int(ps))
    except Exception:
        pass
    return None


# ── Network ────────────────────────────────────────────────────────────────────

async def tcp_ok(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        w.close(); await w.wait_closed(); return True
    except Exception:
        return False


# ── GeoIP (batch, with ASN enrichment) ───────────────────────────────────────

async def batch_geoip(hosts: list[str]) -> dict[str, dict]:
    if not hosts: return {}
    print(f"  GeoIP: {len(hosts)} hosts ...")
    loop = asyncio.get_running_loop()

    def dns(h: str) -> tuple[str, str]:
        try: return h, socket.gethostbyname(h)
        except: return h, ""

    with ThreadPoolExecutor(max_workers=min(150, len(hosts))) as ex:
        pairs = await asyncio.gather(*[loop.run_in_executor(ex, dns, h) for h in hosts])

    h2ip = {h: ip for h, ip in pairs if ip}
    ip2info: dict[str, dict] = {}
    async with aiohttp.ClientSession() as sess:
        for i in range(0, len(h2ip), 100):
            batch = [{"query": ip, "fields": "countryCode,as,mobile,isp"}
                     for ip in list(h2ip.values())[i:i+100]]
            try:
                async with sess.post("http://ip-api.com/batch", json=batch,
                                     timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status == 200:
                        for req, res in zip(batch, await r.json()):
                            if res:
                                asn = (res.get("as","") or "").split(" ")[0]
                                ip2info[req["query"]] = {
                                    "cc":     res.get("countryCode",""),
                                    "asn":    asn,
                                    "isp":    res.get("isp",""),
                                    "mobile": res.get("mobile", False),
                                }
            except Exception as e:
                print(f"  ! GeoIP error: {e}")
            await asyncio.sleep(1.2)

    empty: dict = {"cc":"","asn":"","isp":"","mobile":False}
    return {h: {"ip": ip, **ip2info.get(ip, empty)} for h, ip in h2ip.items()}


# ── Load bootstrap configs from iran-proxy-checker ───────────────────────────

def load_bootstrap() -> list[str]:
    uris: list[str] = []
    base = Path(IRAN_PROXY_CHECKER_DIR)
    for fname in ["armenia_iran_bridge_configs.json", "passing_intranet_configs.json",
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

    for fname in ["armenia_iran_bridge_configs.txt", "passing_intranet_configs.txt",
                  "ir_exit_configs.txt", "ir_mobile_exit_configs.txt",
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


# ── Fetch one source ──────────────────────────────────────────────────────────

async def fetch_source(label: str, url: str, fmt: str,
                       session: aiohttp.ClientSession, retries: int = 2) -> list[str]:
    for attempt in range(retries + 1):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200: return []
                text = await r.text(errors="ignore")
                return extract_uris(decode_b64(text) if fmt == "b64" else text)
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
    print(f"  Bootstrap total: {len(bootstrap)} URIs")

    async with aiohttp.ClientSession(headers=HEADERS) as sess:
        tasks   = [fetch_source(lbl, url, fmt, sess) for lbl, url, fmt in RAW_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for (lbl, _, _), res in zip(RAW_SOURCES, results):
            if isinstance(res, list):
                before = len(all_uris)
                all_uris.update(dict.fromkeys(res))
                new = len(all_uris) - before
                if new: print(f"  + [{lbl}] +{new}", flush=True)

    print(f"\nTotal unique URIs: {len(all_uris)}")
    return list(all_uris)


# ── Verify ────────────────────────────────────────────────────────────────────

async def verify_configs(uris: list[str]) -> list[dict]:
    parsed: list[dict] = []
    unique_hosts: set[str] = set()
    for uri in uris:
        hp = parse_host_port(uri)
        if hp:
            h, p = hp
            if h and 1 <= p <= 65535:
                parsed.append({"uri": uri, "host": h, "port": p,
                                "protocol": classify_proto(uri)})
                unique_hosts.add(h)

    print(f"  Parsed {len(parsed)} configs ({len(uris)-len(parsed)} unparseable)")

    # DNS resolution for fast-path classification
    loop = asyncio.get_running_loop()
    def dns(h: str) -> tuple[str, str]:
        try: return h, socket.gethostbyname(h)
        except: return h, ""

    with ThreadPoolExecutor(max_workers=min(150, len(unique_hosts) or 1)) as ex:
        pairs = await asyncio.gather(*[loop.run_in_executor(ex, dns, h) for h in unique_hosts])

    # Fast-path: Iranian prefix → skip GeoIP API call entirely
    fast_ir:  dict[str, dict] = {}  # host → {asn, operator, mobile}
    fast_am:  set[str]        = set()
    geoip_needed: list[str]   = []

    for host, ip in pairs:
        if not ip:
            geoip_needed.append(host); continue
        op = get_ir_operator(ip)
        if op:
            asn, operator, net_type = op
            fast_ir[host] = {"ip": ip, "asn": asn, "operator": operator,
                              "mobile": asn in MOBILE_ASNS}
        elif any(ip.startswith(p) for p in ARMENIAN_PREFIXES):
            fast_am.add(host)
        else:
            geoip_needed.append(host)

    print(f"  Fast-path IR: {len(fast_ir)} | AM: {len(fast_am)} | GeoIP needed: {len(geoip_needed)}")

    host_info = await batch_geoip(geoip_needed)
    bootstrap_set: set[str] = set(load_bootstrap())

    print(f"  TCP-checking {len(parsed)} configs ...")
    sem = asyncio.Semaphore(MAX_WORKERS)

    async def check_one(cfg: dict) -> dict | None:
        async with sem:
            if not await tcp_ok(cfg["host"], cfg["port"]): return None
            host = cfg["host"]

            if host in fast_ir:
                fp = fast_ir[host]
                asn, operator, is_iran = fp["asn"], fp["operator"], True
                is_mobile = fp["mobile"]
                country = "IR"
            else:
                info      = host_info.get(host, {})
                asn       = info.get("asn","")
                operator  = info.get("isp","")
                is_iran   = (info.get("cc","") == "IR") or (asn in IRAN_ASNS)
                is_mobile = info.get("mobile", False) or (asn in MOBILE_ASNS)
                country   = "IR" if is_iran else info.get("cc","")

            is_armenian = (
                host in fast_am
                or host_info.get(host, {}).get("cc","") == "AM"
                or host_info.get(host, {}).get("asn","") in ARMENIAN_ASNS
            )

            return {
                **cfg,
                "country":          country,
                "asn":              asn,
                "operator":         operator,
                "iran_exit":        is_iran,
                "iran_mobile_exit": is_iran and is_mobile,
                "armenian_bridge":  is_armenian,
                "bridge_verified":  cfg["uri"] in bootstrap_set,
            }

    raw = await asyncio.gather(*[check_one(c) for c in parsed])
    results = [r for r in raw if r is not None]

    # Sort: mobile-IR > IR > bridge-verified > Armenian > other
    # Within each tier: prefer harder-to-block protocols (DPI resilience)
    def sort_key(r: dict) -> tuple:
        tier = (0 if r["iran_mobile_exit"] else
                1 if r["iran_exit"]        else
                2 if r["bridge_verified"]  else
                3 if r["armenian_bridge"]  else 4)
        return (tier, PROTO_ORDER.get(r["protocol"], 7))

    results.sort(key=sort_key)

    ir     = sum(1 for r in results if r["iran_exit"])
    mob    = sum(1 for r in results if r["iran_mobile_exit"])
    am     = sum(1 for r in results if r["armenian_bridge"])
    bv     = sum(1 for r in results if r["bridge_verified"])
    print(f"  Verified: {len(results)} | IR={ir} (mobile={mob}) | "
          f"Armenian={am} | bridge-verified={bv}")
    return results


# ── Write outputs ─────────────────────────────────────────────────────────────

def write_outputs(results: list[dict]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = Path("outputs"); out.mkdir(exist_ok=True)

    ir_r  = [r for r in results if r["iran_exit"]]
    mob_r = [r for r in results if r["iran_mobile_exit"]]
    am_r  = [r for r in results if r["armenian_bridge"]]

    header = (f"# Iran Intranet Configs — {now}\n"
              f"# {len(results)} configs | IR={len(ir_r)} (mobile={len(mob_r)}) "
              f"| Armenian={len(am_r)}\n"
              f"# Sorted: IR-mobile > IR-exit > bridge-verified > Armenian\n"
              f"# Within tier: TUIC > Hysteria2 > VLESS > Trojan > VMess > SS\n")

    # Subscription file — bare URIs only (parsers require this)
    with open(out/"passing_intranet_configs.txt","w",encoding="utf-8") as f:
        f.write(header + "# Import in Hiddify / v2rayNG / NekoBox / Xray\n\n")
        for r in results: f.write(r["uri"] + "\n")

    # IR-exit only
    with open(out/"ir_exit_configs.txt","w",encoding="utf-8") as f:
        f.write(f"# IR-exit configs — {now}\n# {len(ir_r)} configs\n\n")
        for r in ir_r: f.write(r["uri"] + "\n")

    # Mobile-ISP exit (most resilient during shutdowns)
    with open(out/"ir_mobile_exit_configs.txt","w",encoding="utf-8") as f:
        f.write(f"# IR mobile-ISP exit (MCI/Irancell/Rightel) — {now}\n")
        f.write(f"# {len(mob_r)} configs — last operators to go offline\n\n")
        for r in mob_r: f.write(r["uri"] + "\n")

    # Armenian bridge
    with open(out/"armenian_bridge_configs.txt","w",encoding="utf-8") as f:
        f.write(f"# Armenian bridge configs — {now}\n# {len(am_r)} configs\n\n")
        for r in am_r: f.write(r["uri"] + "\n")

    # JSON with metadata
    with open(out/"passing_intranet_configs.json","w",encoding="utf-8") as f:
        json.dump({
            "checked_at": now,
            "count": len(results),
            "summary": {
                "ir_exit": len(ir_r), "ir_mobile": len(mob_r), "armenian": len(am_r),
            },
            "configs": results,
        }, f, indent=2, ensure_ascii=False)

    # Base64 subscription blob
    with open(out/"passing_intranet_configs_base64.txt","w") as f:
        f.write(base64.b64encode("\n".join(r["uri"] for r in results).encode()).decode())

    # Per-protocol splits
    proto_dir = out/"by_protocol"; proto_dir.mkdir(exist_ok=True)
    protos = ["tuic","hysteria2","vless","trojan","vmess","ss","wireguard","other"]
    buckets: dict[str,list[str]] = {p: [] for p in protos}
    for r in results: buckets[r["protocol"]].append(r["uri"])
    for proto, uris in buckets.items():
        if uris:
            with open(proto_dir/f"{proto}.txt","w",encoding="utf-8") as f:
                f.write(f"# {proto.upper()} — {now}\n# {len(uris)} configs\n\n")
                for u in uris: f.write(u + "\n")

    print(f"\nOutputs → outputs/")
    print(f"  passing_intranet_configs.txt    ({len(results)})")
    print(f"  ir_exit_configs.txt             ({len(ir_r)})")
    print(f"  ir_mobile_exit_configs.txt      ({len(mob_r)})")
    print(f"  armenian_bridge_configs.txt     ({len(am_r)})")
    print(f"  passing_intranet_configs.json")
    print(f"  passing_intranet_configs_base64.txt")
    for p in protos:
        n = len(buckets[p])
        if n: print(f"  by_protocol/{p}.txt         ({n})")


# ── Minimum config check ──────────────────────────────────────────────────────

def check_minimum(results: list[dict]) -> None:
    if len(results) < MIN_PASSING_CONFIGS:
        print(f"\nERROR: Only {len(results)} configs passed "
              f"(minimum: {MIN_PASSING_CONFIGS}). "
              f"Check source availability.", file=sys.stderr)
        sys.exit(1)


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    sep = "=" * 55
    print(sep)
    print("Iran Intranet Config Collector  (Direction A)")
    print(f"TCP timeout  : {TCP_TIMEOUT}s  |  max workers: {MAX_WORKERS}")
    print(f"Min configs  : {MIN_PASSING_CONFIGS}")
    print(sep)
    t0 = time.monotonic()

    print("\n[1/3] Collecting configs ...")
    uris = await collect_all()

    print(f"\n[2/3] Verifying {len(uris)} configs ...")
    results = await verify_configs(uris)

    check_minimum(results)

    print("\n[3/3] Writing outputs ...")
    write_outputs(results)

    print(f"\n{sep}")
    print(f"Done in {time.monotonic()-t0:.0f}s — {len(results)} configs.")
    print(sep)


if __name__ == "__main__":
    asyncio.run(main())
