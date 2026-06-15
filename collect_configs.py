#!/usr/bin/env python3
"""
Iran Intranet Config Collector & Verifier  v5.1 + multi-API GeoIP patch
========================================================================
Direction A — Diaspora / researchers OUTSIDE Iran → SHOMA

Changes in v5.1 (source overhaul):
• REMOVED ebrasha/all (all_extracted_configs.txt, ~196k entries) — that single
  file caused the GitHub Actions job to be cancelled after 30+ minutes because
  196k configs × (TCP_TIMEOUT + HTTP probe) / 60 workers = many hours to verify.
  Investigation confirmed the collection script is CLOSED-SOURCE (1-commit repo,
  no public GitHub Actions, driven by a private Telegram bot — AbdalV2rayBot).
  There is no public source list to replicate directly.
• REPLACED ebrasha/all with ebrasha’s own per-protocol split files (each capped
  independently by MAX_URIS_PER_SOURCE so no single file can blow up the run):
    ebrasha/curated  → V2Ray-Config-By-EbraSha.txt  (hand-tested, intentionally small)
    ebrasha/vmess    → vmess_configs.txt
    ebrasha/vless    → vless_configs.txt
    ebrasha/trojan   → trojan_configs.txt
    ebrasha/ss       → ss_configs.txt
• ADDED new Iran-exit sources not previously in the list:
    Surfboardv2ray/TGParse          — Telegram parser, per-protocol Iran splits
    HosseinKoofi/GO_V2rayCollector  — Go collector, mixed/vless/ss Iran splits
    youfoundamin/V2rayCollector     — vless_iran + ss_iran
    Stinsonysm/GO_V2rayCollector    — trojan_iran
    4n0nymou3/multi-proxy-config-fetcher — broad multi-protocol aggregator
• MAX_URIS_PER_SOURCE default lowered: 30 000 → 4 000
• MAX_TOTAL_URIS global ceiling added (default 25 000) — hard cap before verification
• Original v5 features retained: Armenia CIDR fast-path, Iran-bridge test,
  multi-API GeoIP cross-check, security scoring, per-protocol outputs.
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
HTTP_TIMEOUT           = int(  os.environ.get("HTTP_TIMEOUT",         "5"))
MAX_WORKERS            = int(  os.environ.get("MAX_WORKERS",           "60"))
SKIP_V2RAY_TEST        = os.environ.get("SKIP_V2RAY_TEST",    "1").strip() == "1"
MIN_PASSING_CONFIGS    = int(  os.environ.get("MIN_PASSING_CONFIGS",   "10"))
PROBE_ENABLED          = os.environ.get("PROBE_ENABLED",      "1").strip() == "1"
SKIP_IRAN_BRIDGE       = os.environ.get("SKIP_IRAN_BRIDGE",   "1").strip() == "1"
IRAN_BRIDGE_TIMEOUT    = int(  os.environ.get("IRAN_BRIDGE_TIMEOUT",  "8"))

# ── Iranian IP prefix registry ─────────────────────────────────────────────────
IRANIP_PREFIXES: tuple[tuple[str, str, str], ...] = (
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
("91.108.4.",  "AS62282",  "Fanap"),    ("91.108.8.", "AS62282",  "Fanap"),
("213.176.",   "AS49100",  "ParsOnline"),
("62.193.",    "AS25184",  "Afranet"),
("185.167.",   "AS42337",  "Respina"),
("94.182.",    "AS197398", "HiWeb"), ("94.183.", "AS197398", "HiWeb"),
# IPM Research
("212.16.",    "AS12660",  "IPM"),
)
_IRAN_PREFIXES = tuple(p for p, _, _ in IRANIP_PREFIXES)
IRAN_ASNS: frozenset[str] = frozenset({
    "AS12880","AS58224","AS197207","AS44244","AS57218","AS48159","AS34369",
    "AS214922","AS205347","AS207719","AS43754","AS210362","AS62282","AS49100",
    "AS25184","AS42337","AS197398","AS12660","AS6736","AS44285","AS47262",
    "AS31549","AS16322","AS50810","AS34832",
})
MOBILE_ASNS: frozenset[str] = frozenset({"AS197207","AS44244","AS57218"})

# ── PATCH 1: Multi-API GeoIP Cross-Check ──────────────────────────────────────
_GEOIP_SECONDARY = [
    ("ipapi.co",  "https://ipapi.co/{ip}/json/",  "country_code", "asn"),
    ("ipinfo.io", "https://ipinfo.io/{ip}/json",   "country",      "org"),
]

_SHARED_SESSION: aiohttp.ClientSession | None = None

async def verify_iran_exit_multiapi(
    ip: str,
    session: aiohttp.ClientSession,
    primary_vote: bool,
) -> tuple[int, int]:
    """
    Cross-check ip against two additional GeoIP APIs.
    Returns (total_votes, max_possible_votes).
    """
    votes = int(primary_vote)
    checked = 1
    for name, url_tmpl, cc_field, org_field in _GEOIP_SECONDARY:
        try:
            async with session.get(
                url_tmpl.format(ip=ip),
                timeout=aiohttp.ClientTimeout(total=8),
                headers={"Accept": "application/json"},
            ) as r:
                if r.status != 200:
                    continue
                data = await r.json(content_type=None)
                cc  = (data.get(cc_field) or "").strip().upper()
                org = (data.get(org_field) or "").strip().upper()
                asn = org.split()[0] if org else ""
                if cc == "IR" or asn in IRAN_ASNS:
                    votes += 1
                checked += 1
        except Exception:
            pass
    return votes, checked

# ── Armenia CIDR registry ──────────────────────────────────────────────────────
ARMENIAN_PREFIXES = ("5.10.214.","5.10.215.","188.164.158.","188.164.159.")
ARMENIAN_ASNS: frozenset[str] = frozenset({"AS42910","AS43733","AS49800"})
ARMENIA_CIDR_URLS = [
    "https://www.ipdeny.com/ipblocks/data/countries/am.zone",
    "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/am.cidr",
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/am/ipv4-aggregated.txt",
]
_ARMENIA_FALLBACK_CIDRS = [
    "5.105.0.0/16",   "77.92.0.0/17",    "85.105.0.0/16",  "176.74.0.0/15",
    "46.70.0.0/15",   "91.194.168.0/21",
    "84.234.0.0/17",  "94.43.128.0/17",
    "109.75.0.0/16",  "213.135.64.0/18",
    "37.252.64.0/18", "212.34.32.0/19",
    "91.210.172.0/22","91.214.44.0/22",   "185.4.212.0/22", "185.40.240.0/22",
    "185.112.144.0/22","185.130.44.0/22","185.183.96.0/22","185.200.116.0/22",
    "193.200.200.0/22","194.9.24.0/21",  "194.67.216.0/21","195.34.32.0/19",
    "212.92.128.0/18",
]
IRAN_TEST_ENDPOINTS = [
    ("5.160.0.1",     80), ("78.38.0.1",     80), ("151.232.0.1",   80),
    ("185.112.32.1",  80), ("185.141.104.1", 80), ("185.173.128.1", 80),
    ("5.200.200.200", 80),
]
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
        if pat.search(uri): return None
    uri = uri.replace("%2C", ",").replace("%28", "(").replace("%29", ")")
    uri = re.sub(r"#\s*$", "", uri.strip())
    return uri if uri else None

def _uuid_from_uri(uri: str) -> str | None:
    uuid_re = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
    m = uuid_re.search(uri)
    return m.group(0).lower() if m else None

def _is_reality(uri: str) -> bool:
    return "reality" in uri.lower() or "xtls-rprx-vision" in uri.lower()

def _quality_score(uri: str) -> int:
    uri_l = uri.lower()
    proto  = uri_l.split("://")[0]
    if _is_reality(uri): return 4
    has_tls  = "security=tls" in uri_l or "tls" in uri_l
    port_443 = ":443" in uri or "port=443" in uri_l
    iranian_cdn_hosts = ("185.143.", "185.51.200.", "snapp.ir", "snapp.doctor", "arvancloud.ir", "arvancaas.ir")
    is_ir_cdn_front = any(h in uri for h in iranian_cdn_hosts)
    if is_ir_cdn_front and not has_tls: return -1
    if proto in ("hysteria2", "hy2", "tuic"): return 3
    if has_tls and port_443: return 3
    if has_tls: return 2
    return 1

MIN_QUALITY_SCORE = int(os.environ.get("MIN_QUALITY_SCORE", "0"))

# ── Security Checks ────────────────────────────────────────────────────────────
# Minimum security score to include a config in any output (0–10, default 3).
# Set to 0 to disable security filtering entirely.
MIN_SECURITY_SCORE = int(os.environ.get("MIN_SECURITY_SCORE", "3"))

# Shadowsocks cipher classification
_SS_WEAK_CIPHERS: frozenset[str] = frozenset({
    # Unauthenticated / no AEAD → vulnerable to active tampering
    "none", "table",
    "rc4", "rc4-md5",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
    "salsa20", "chacha20", "chacha20-ietf",   # non-IETF / no-MAC variants
})
_SS_AEAD_CIPHERS: frozenset[str] = frozenset({
    # Authenticated encryption — safe against active probing & replay
    "aes-128-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
})

# Ports that naturally carry HTTPS/QUIC — less likely to be blocked or flagged
_SECURE_PORTS: frozenset[int] = frozenset({443, 8443, 2053, 2083, 2087, 2096})


def _get_ss_cipher(uri: str) -> str:
    """Extract the Shadowsocks cipher method from a ss:// URI. Returns '' on failure."""
    try:
        body = uri[5:].split("#")[0].split("?")[0]
        if "@" in body:
            # SIP002 format: ss://userinfo@host:port
            # userinfo may be base64(method:password) or plain method:password
            userinfo = body.rsplit("@", 1)[0]
            try:
                decoded = base64.b64decode(
                    userinfo + "=" * (-len(userinfo) % 4)
                ).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    return decoded.split(":")[0].lower()
            except Exception:
                pass
            if ":" in userinfo:
                return userinfo.split(":")[0].lower()
        else:
            # Legacy format: ss://base64(method:password@host:port)
            raw = body + "=" * (-len(body) % 4)
            dec = base64.b64decode(raw).decode("utf-8", errors="ignore")
            if ":" in dec:
                return dec.split(":")[0].lower()
    except Exception:
        pass
    return ""


def _get_vmess_alterid(uri: str) -> int:
    """
    Return VMess alterId (aid field).
      0   → AEAD mode (secure, recommended)
      >0  → legacy UUID-based encryption (weaker, replay-vulnerable)
      -1  → parse error
    """
    try:
        raw = uri[8:] + "=" * (-(len(uri) - 8) % 4)
        obj = json.loads(base64.b64decode(raw).decode("utf-8", errors="ignore"))
        return int(obj.get("aid", 0))
    except Exception:
        return -1


def _score_config_security(uri: str, port: int, latency_ms: float) -> tuple[int, list[str]]:
    """
    Compute (security_score, security_flags) for a verified config URI.

    Score tiers (0–10)
    ──────────────────
    7–10  Reality       — mimics real TLS 1.3; gold standard for DPI resistance
    5–6   QUIC-based    — TUIC / Hysteria2; built-in AEAD, no extra TLS needed
    4–6   TLS-wrapped   — VLESS/Trojan/VMess with TLS and good settings
    2–3   TLS with       caveats (no SNI, legacy VMess alterId, unrecognized SS cipher)
    0–1   No encryption  or known-weak cipher → filtered out at MIN_SECURITY_SCORE

    Controlled by env var MIN_SECURITY_SCORE (default 3).
    """
    score: int = 0
    flags: list[str] = []
    proto = classify_proto(uri)
    uri_l = uri.lower()

    # Detect explicit TLS (covers VLESS ?security=tls, Trojan, VMess JSON "tls")
    has_tls = (
        "security=tls" in uri_l
        or ("tls" in uri_l and "notls" not in uri_l and "no-tls" not in uri_l)
    )

    # ── Per-protocol base score ────────────────────────────────────────────────
    if _is_reality(uri):
        # VLESS + XTLS-Reality: impersonates a real TLS 1.3 website fingerprint
        score = 7

    elif proto in ("hysteria2", "tuic"):
        # QUIC-based protocols with mandatory AEAD; TLS-equivalent by design
        score = 5

    elif proto == "wireguard":
        # ChaCha20-Poly1305 encryption; BUT distinctive fixed-size handshake
        score = 4
        flags.append("wireguard_dpi_detectable")

    elif proto in ("vless", "trojan"):
        if has_tls:
            score = 4
        else:
            score = 1
            flags.append("no_tls")

    elif proto == "vmess":
        aid = _get_vmess_alterid(uri)
        if has_tls:
            score = 3
            if aid == 0:
                score += 1          # AEAD mode — authenticated encryption
            else:
                flags.append("vmess_legacy_aid")   # alterId>0: older, weaker UUID mode
        else:
            score = 1
            flags.append("no_tls")
            if aid > 0:
                flags.append("vmess_legacy_aid")

    elif proto == "ss":
        cipher = _get_ss_cipher(uri)
        if cipher in _SS_AEAD_CIPHERS:
            score = 4
        elif cipher in _SS_WEAK_CIPHERS:
            # Non-authenticated: vulnerable to active probing and replay
            score = 0
            flags.append(f"weak_ss_cipher:{cipher}")
        elif cipher == "":
            score = 2
            flags.append("ss_cipher_undetectable")
        else:
            score = 2
            flags.append(f"ss_unrecognized_cipher:{cipher}")

    else:
        score = 1

    # ── Port bonus / penalty ───────────────────────────────────────────────────
    if port in _SECURE_PORTS:
        score += 1                  # standard HTTPS/QUIC port — blends in
    elif port == 80:
        flags.append("plaintext_port_80")
        score = max(0, score - 1)  # plain HTTP port — easily inspected

    # ── SNI presence check for TLS configs ────────────────────────────────────
    if has_tls and proto not in ("hysteria2", "tuic", "wireguard"):
        has_sni = "sni=" in uri_l or "servername=" in uri_l
        if has_sni:
            score += 1              # SNI set: TLS handshake can mimic a legit site
        else:
            flags.append("no_sni")

    # ── Latency quality signal ─────────────────────────────────────────────────
    if latency_ms > 5000:
        flags.append("very_high_latency")
        score = max(0, score - 1)  # extremely slow — likely unreliable in practice
    elif latency_ms > 3000:
        flags.append("high_latency")

    return min(10, score), flags


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
            if _is_reality(uri) and not _is_reality(prev): best[uid] = uri
            elif "security=tls" in uri and "security=tls" not in prev: best[uid] = uri
            elif len(uri) < len(prev) and not _is_reality(prev): best[uid] = uri
    return list(best.values()) + no_uuid

# ── Additional deduplication passes ───────────────────────────────────────────
_FRAG_RE = re.compile(r"#.*$")

def deduplicate_by_normalized_uri(uris: list[str]) -> list[str]:
    """
    Pass 1 — strip the #fragment (channel name / label) and compare the bare URI.

    Aggregators append their Telegram channel name as a comment, so the same
    config appears dozens of times across sources:
        vless://uuid@server:443?...#Channel_A
        vless://uuid@server:443?...#FreeVPN_Bot
        vless://uuid@server:443?...#مجانی

    All three are byte-for-byte identical after the '#'.  dict.fromkeys in
    collect_all() already removed exact duplicates, but these survive because
    the fragments differ.  This pass collapses them to one.

    The first occurrence wins (sources are already ordered best-first because
    high-quality repos like barry-far appear before bulk dumps).
    """
    seen: dict[str, str] = {}   # normalised_uri → first_original_uri
    for uri in uris:
        norm = _FRAG_RE.sub("", uri).rstrip()
        if norm not in seen:
            seen[norm] = uri
    return list(seen.values())


def deduplicate_by_server(uris: list[str]) -> list[str]:
    """
    Pass 2 — one config per (host, port) endpoint.

    This is the primary logic behind NekoBox's 'Remove Duplicates'.  If ten
    configs all point to the same host:port they will ALL connect to the same
    physical server, making nine of them useless.  We keep the one with the
    highest protocol quality (Reality > TLS+443 > TLS > plain).

    parse_host_port() is called here at runtime so forward-reference is fine.
    """
    best: dict[tuple[str, int], str] = {}   # (host, port) → best URI
    unparseable: list[str] = []

    for uri in uris:
        hp = parse_host_port(uri)
        if hp is None:
            unparseable.append(uri)
            continue
        key = (hp[0].lower(), hp[1])
        if key not in best:
            best[key] = uri
        else:
            prev = best[key]
            qs_new  = _quality_score(uri)
            qs_prev = _quality_score(prev)
            if _is_reality(uri) and not _is_reality(prev):
                best[key] = uri
            elif not _is_reality(prev) and qs_new > qs_prev:
                best[key] = uri
            elif qs_new == qs_prev and len(uri) < len(prev):
                best[key] = uri

    return list(best.values()) + unparseable

# ── URI parsing ────────────────────────────────────────────────────────────────
def decode_b64(text: str) -> str:
    s = text.strip().replace("\n", "").replace("\r", "")
    try:
        if not URI_RE.search(text[:200]):
            p = s + "=" * (-len(s) % 4)
            d = base64.b64decode(p).decode("utf-8", errors="ignore")
            if URI_RE.search(d[:200]): return d
    except Exception: pass
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
            if "@" in body: hp = body.rsplit("@",1)[1]
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
    except Exception: pass
    return None

# ── Armenia CIDR loader ────────────────────────────────────────────────────────
def _load_armenia_networks_sync() -> list[ipaddress.IPv4Network]:
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
                    try: nets.append(ipaddress.IPv4Network(m.group(1), strict=False))
                    except ValueError: pass
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
    if _ARMENIA_NETWORKS is None: _ARMENIA_NETWORKS = _load_armenia_networks_sync()
    return _ARMENIA_NETWORKS

def _ip_in_armenia(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in _get_armenia_networks())
    except ValueError: return False

# ── Network helpers ────────────────────────────────────────────────────────────
async def tcp_ok(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> float | None:
    try:
        t0 = time.monotonic()
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        lat = (time.monotonic() - t0) * 1000
        w.close(); await w.wait_closed()
        return round(lat, 1)
    except Exception: return None

async def http_probe(host: str, port: int, uri: str, timeout: float = 8.0) -> bool:
    if not PROBE_ENABLED: return True
    proto   = classify_proto(uri)
    ws_path = "/"
    ws_host = host
    if "path=" in uri:
        try:
            m = re.search(r"path=([^&]+)", uri)
            if m:
                import urllib.parse
                ws_path = urllib.parse.unquote(m.group(1))
        except Exception: pass
    if "host=" in uri:
        try:
            m = re.search(r"host=([^&#]+)", uri)
            if m: ws_host = m.group(1)
        except Exception: pass
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
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=True), timeout=timeout)
        else:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.write(request); await w.drain()
        data = await asyncio.wait_for(r.read(512), timeout=timeout)
        w.close()
        if not data: return False
        if data[:4].startswith(b"HTTP"):
            status_line = data.split(b"\r\n")[0].decode("utf-8","ignore")
            try: code = int(status_line.split(" ")[1])
            except (IndexError, ValueError): return True
            if code in (101, 200, 400, 405, 407): return True
            if code in (404, 403) and b"<html" in data.lower(): return False
            return True
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError): return False
    except Exception: return True

# ── Iran-bridge test ───────────────────────────────────────────────────────────
async def iran_bridge_test(host: str, port: int) -> tuple[bool, str | None]:
    if SKIP_IRAN_BRIDGE: return True, "skipped"
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
                    if resp.status < 600: return True, iran_ip
            except aiohttp.ClientProxyConnectionError: continue
            except aiohttp.ServerConnectionError: return True, iran_ip
            except Exception: continue
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
            batch = [{"query":ip,"fields":"countryCode,as,mobile,isp"} for ip in list(h2ip.values())[i:i+100]]
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
    ("barry-far/vmess",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",    "text"),
    ("barry-far/vless",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",    "text"),
    ("barry-far/ss",      "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",       "text"),
    ("barry-far/trojan",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",   "text"),
    ("barry-far/hy2",     "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/hysteria2.txt","text"),
    ("barry-far/all",     "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Config_base64_Sub.txt",          "b64"),
    # ── ebrasha: replaced "ebrasha/all" (all_extracted_configs.txt, ~196k entries) ─
    # The all_extracted_configs.txt is a private closed-source Telegram-bot aggregate;
    # its collection script is not public (only 1 commit, no Actions visible).
    # We use the per-protocol split files instead — same content but each capped
    # independently by MAX_URIS_PER_SOURCE, so no single file can blow up the run.
    # The curated file (V2Ray-Config-By-EbraSha.txt) contains ebrasha's own/hand-
    # tested servers and is intentionally small — always include it uncapped.
    ("ebrasha/curated",  "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha.txt",     "text"),
    ("ebrasha/vmess",    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vmess_configs.txt",               "text"),
    ("ebrasha/vless",    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vless_configs.txt",               "text"),
    ("ebrasha/trojan",   "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/trojan_configs.txt",              "text"),
    ("ebrasha/ss",       "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/ss_configs.txt",                  "text"),
    # ── Iran-exit focused sources (new — not previously in list) ─────────────────
    # Surfboardv2ray/TGParse: Telegram-channel parser, per-protocol splits,
    # actively maintained with Iranian exit focus.
    ("tgparse/vless",    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",   "text"),
    ("tgparse/trojan",   "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/trojan",  "text"),
    ("tgparse/ss",       "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/ss",      "text"),
    # HosseinKoofi/GO_V2rayCollector: Go-based collector with dedicated Iran-exit
    # splits (mixed_iran, vless_iran, ss_iran).
    ("hkofi/mixed-ir",   "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",  "text"),
    ("hkofi/vless-ir",   "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",  "text"),
    ("hkofi/ss-ir",      "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",     "text"),
    # youfoundamin/V2rayCollector: another Iran-exit collector.
    ("amin/vless-ir",    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",     "text"),
    ("amin/ss-ir",       "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/ss_iran.txt",        "text"),
    # Stinsonysm/GO_V2rayCollector: Iran-exit Trojan configs from Telegram.
    ("stinson/trojan-ir","https://raw.githubusercontent.com/Stinsonysm/GO_V2rayCollector/main/trojan_iran.txt",   "text"),
    # 4n0nymou3/multi-proxy-config-fetcher: broad multi-protocol aggregator.
    ("4n0n/proxy",       "https://github.com/4n0nymou3/multi-proxy-config-fetcher/raw/refs/heads/main/configs/proxy_configs.txt","text"),
    ("matin/super",       "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt","b64"),
    ("matin/vmess",       "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",    "text"),
    ("matin/vless",       "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",    "text"),
    ("matin/ss",          "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",       "text"),
    ("matin/trojan",      "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",   "text"),
    ("matin/hy2",         "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt","text"),
    ("epodonios/AM",      "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Armenia/config.txt","text"),
    ("epodonios/IR",      "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Iran/config.txt",   "text"),
    ("epodonios/sub1",    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt","b64"),
    ("shatak/all",        "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt","text"),
    ("solispirit/AM-vmess","https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vmess.txt","text"),
    ("solispirit/AM-vless","https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vless.txt","text"),
    ("solispirit/vless",   "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/vless.txt",    "text"),
    ("solispirit/tuic",    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/tuic.txt",     "text"),
    ("solispirit/hy2",     "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/hysteria2.txt","text"),
    ("yebekhe/mix",       "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mix_base64",       "b64"),
    ("yebekhe/reality",   "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/reality",   "text"),
    ("yebekhe/vmess",     "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vmess",     "text"),
    ("yebekhe/vless",     "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless",     "text"),
    ("yebekhe/trojan",    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/trojan",    "text"),
    ("yebekhe/hy2",       "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/hysteria2", "text"),
    ("soroush/vmess",     "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess",       "text"),
    ("soroush/vless",     "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",       "text"),
    ("soroush/trojan",    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",      "text"),
    ("soroush/ss",        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/shadowsocks", "text"),
    ("soroush/hy2",       "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria2",   "text"),
    ("nirevil/sub",       "https://raw.githubusercontent.com/NiREvil/vless/main/sub/G",          "b64"),
    ("nirevil/hy2",       "https://raw.githubusercontent.com/NiREvil/vless/main/sub/hysteria2",  "text"),
    ("f0rc3run/vmess",    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vmess.txt",   "text"),
    ("f0rc3run/vless",    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",   "text"),
    ("f0rc3run/trojan",   "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/trojan.txt",  "text"),
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
    ("arshia/vless",      "https://raw.githubusercontent.com/arshiacomplus/v2rayTemplet/main/vless.txt",                "text"),
    ("mhdi/all",          "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Mix/mix.txt",        "b64"),
    ("iranfilter/all",    "https://raw.githubusercontent.com/IranFilteredConfig/Free-Configs/main/sub/all.txt",          "b64"),
    ("shadowshare/am",    "https://raw.githubusercontent.com/ShadowShare/ShadowShare/main/AM.txt",                       "text"),
    ("kort0881/vless",    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/vless.txt",          "text"),
    ("rooster/reality",   "https://raw.githubusercontent.com/roosterkid/openproxylist/main/VLESS_RAW.txt",               "text"),
    ("reality-ir/vless",  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/vless.txt",                   "text"),
    ("reality-collect",   "https://raw.githubusercontent.com/M677871/xtls-reality-configs/main/configs.txt",             "text"),
    ("hy2-collect/all",   "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",      "b64"),
    ("v2nodes/AM",        "https://www.v2nodes.com/country/am/",         "html"),
    ("openproxylist/AM",  "https://openproxylist.com/v2ray/country/am/", "html"),
]
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; IranIntranetCollector/5.0)"}

# ── Bootstrap from iran-proxy-checker ────────────────────────────────────────
def load_bootstrap() -> list[str]:
    uris: list[str] = []
    base = Path(IRAN_PROXY_CHECKER_DIR)
    for fname in ["armenia_iran_bridge_configs.json","passing_intranet_configs.json", "working_armenia_configs.json"]:
        fpath = base / fname
        if not fpath.exists(): continue
        try:
            data    = json.loads(fpath.read_text(encoding="utf-8"))
            configs = data.get("configs") or data.get("outbounds") or []
            before  = len(uris)
            for e in configs:
                u = e.get("uri") or e.get("config_uri","")
                if u and URI_RE.match(u): uris.append(u)
            if len(uris) > before: print(f"  bootstrap [{fname}]: +{len(uris)-before}")
        except Exception as e: print(f"  bootstrap [{fname}]: {e}")
    for fname in ["armenia_iran_bridge_configs.txt","passing_intranet_configs.txt",
                  "ir_exit_configs.txt","ir_mobile_exit_configs.txt", "passing_intranet_configs_base64.txt"]:
        fpath = base / fname
        if not fpath.exists(): continue
        try:
            new = extract_uris(fpath.read_text(encoding="utf-8"))
            uris.extend(new)
            if new: print(f"  bootstrap [{fname}]: +{len(new)}")
        except Exception as e: print(f"  bootstrap [{fname}]: {e}")
    return list(dict.fromkeys(uris))

# ── Scraper ───────────────────────────────────────────────────────────────────
async def fetch_source(label: str, url: str, fmt: str, session: aiohttp.ClientSession, retries: int = 2) -> list[str]:
    # Read the limit from the YAML env (defaults to 9000 if not set)
    MAX_PER_SOURCE = int(os.environ.get("MAX_URIS_PER_SOURCE", "9000"))
    # and the three dedup passes (URI / UUID / server) cut the list
    # dramatically before it ever reaches the TCP+probe stage.
    for attempt in range(retries + 1):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200: return []
                text = await r.text(errors="ignore")
                if fmt == "b64":
                    return extract_uris(decode_b64(text))
                else:
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

    # ── Three dedup passes (mirrors NekoBox "Remove Duplicates") ─────────────
    # Pass 0 — exact URI match (already done by dict.fromkeys above)
    # Pass 1 — strip #fragment, compare bare URI (same config, different label)
    after_uri  = deduplicate_by_normalized_uri(list(all_uris))
    # Pass 2 — same UUID → keep best security (Reality > TLS > plain)
    after_uuid = deduplicate_by_uuid(after_uri)
    # Pass 3 — same host:port → keep best (one config per physical server)
    after_srv  = deduplicate_by_server(after_uuid)

    filtered = [u for u in after_srv if _quality_score(u) >= MIN_QUALITY_SCORE]
    dropped  = len(after_srv) - len(filtered)

    print(f"\nCollected {raw_count} raw URIs")
    print(f"  → {len(after_uri)}  after fragment-strip dedup  (−{raw_count - len(after_uri)}  label variants)")
    print(f"  → {len(after_uuid)} after UUID dedup             (−{len(after_uri) - len(after_uuid)} same-UUID dupes)")
    print(f"  → {len(after_srv)}  after server dedup           (−{len(after_uuid) - len(after_srv)} same-server dupes)")
    print(f"  → {len(filtered)}   after quality filter          (−{dropped} quality<{MIN_QUALITY_SCORE})")

    # Global ceiling: final safety net so verification time stays predictable.
    MAX_TOTAL = int(os.environ.get("MAX_TOTAL_URIS", "25000"))
    if len(filtered) > MAX_TOTAL:
        print(f"  → {MAX_TOTAL}   after global cap              (−{len(filtered) - MAX_TOTAL} truncated, MAX_TOTAL_URIS={MAX_TOTAL})")
        filtered = filtered[:MAX_TOTAL]

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
        match = next(((asn, op) for pfx, asn, op in IRANIP_PREFIXES if ip.startswith(pfx)), None)
        if match:
            asn, op = match
            fast_ir[host] = {"ip":ip,"asn":asn,"operator":op,"mobile":asn in MOBILE_ASNS}
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
            latency = await tcp_ok(host, port)
            if latency is None: return None
            if not await http_probe(host, port, uri): return None

            if host in fast_ir:
                fp = fast_ir[host]
                asn, operator, is_iran, is_mobile = (fp["asn"], fp["operator"], True, fp["mobile"])
                country = "IR"
                host_ip = fp["ip"]
            else:
                info     = host_info.get(host, {})
                asn      = info.get("asn","")
                operator = info.get("isp","")
                is_iran  = (info.get("cc","")=="IR") or (asn in IRAN_ASNS)
                is_mobile= info.get("mobile",False) or (asn in MOBILE_ASNS)
                country  = "IR" if is_iran else info.get("cc","")
                host_ip  = info.get("ip", "")

            is_armenian = (
                host in fast_am
                or host_info.get(host,{}).get("cc","") == "AM"
                or host_info.get(host,{}).get("asn","") in ARMENIAN_ASNS
            )

            # ── PATCH: multi-API GeoIP cross-check for Iranian exits ─────────────
            multiapi_iran_votes = 0
            if is_iran and host_ip:
                votes, out_of = await verify_iran_exit_multiapi(host_ip, _SHARED_SESSION, primary_vote=True)
                multiapi_iran_votes = votes
            elif host_ip:
                votes, out_of = await verify_iran_exit_multiapi(host_ip, _SHARED_SESSION, primary_vote=False)
                multiapi_iran_votes = votes
                if votes >= 2:
                    is_iran  = True
                    country  = "IR"

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
                "multiapi_iran_votes": multiapi_iran_votes,
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
def _write_iran_appearing_outputs(results: list[dict], out, now: str) -> tuple[list[dict], list[dict], list[dict]]:
    ir_only = [r for r in results if r["iran_exit"] and not r["armenian_bridge"]]
    strict  = [r for r in ir_only if r.get("multiapi_iran_votes", 0) >= 3]
    normal  = [r for r in ir_only if r.get("multiapi_iran_votes", 0) >= 2]
    loose   = ir_only

    for fname, subset, label, note in [
        (
            "iran_appearing_strict.txt", strict,
            "Iranian-exit (3/3 GeoIP APIs confirmed) — websites will see you as in Iran",
            "Highest confidence: all three GeoIP APIs (ip-api.com, ipapi.co, ipinfo.io) agree."
        ),
        (
            "iran_appearing.txt", normal,
            "Iranian-exit (≥2/3 GeoIP APIs confirmed) — websites will see you as in Iran",
            "Recommended: majority vote across 3 independent GeoIP services.\n"
            "Use this if you need your exit IP to appear Iranian to external sites."
        ),
        (
            "iran_appearing_loose.txt", loose,
            "Iranian-exit (ip-api.com confirmed) — same as ir_exit_configs.txt",
            "Kept for backward compatibility. Equivalent to ir_exit_configs.txt."
        ),
    ]:
        with open(out / fname, "w", encoding="utf-8") as f:
            f.write(f"# {label}\n")
            f.write(f"# {note}\n")
            f.write(f"# Generated: {now} | {len(subset)} configs\n")
            f.write("#\n")
            f.write("# NOT included: armenian_bridge configs — those show Armenian IPs to sites.\n\n")
            for r in subset:
                f.write(r["uri"] + "\n")
    return strict, normal, loose

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
        f.write(header + "# Import: use raw.githubusercontent.com, not github.com/blob/\n")
        for r in results: f.write(r["uri"]+"\n")
    for fname, subset, label in [
        ("ir_exit_configs.txt",          ir_r,   "IR-exit (confirmed Iranian IP)"),
        ("ir_mobile_exit_configs.txt",   mob_r,  "IR mobile (MCI/Irancell/Rightel)"),
        ("armenian_bridge_configs.txt",  am_r,   "Armenian corridor bridge (all)"),
        ("iran_bridge_configs.txt",      ib_r,   "Armenia→Iran bridge-verified"),
        ("ir_reality_configs.txt",       real_r, "IR-exit + VLESS Reality (best DPI resistance)"),
    ]:
        with open(out/fname,"w",encoding="utf-8") as f:
            f.write(f"# {label} — {now}\n# {len(subset)} configs\n")
            for r in subset: f.write(r["uri"]+"\n")
            
    strict, normal, loose = _write_iran_appearing_outputs(results, out, now)

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
                "iran_appearing_strict": len(strict),
                "iran_appearing": len(normal),
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
                f.write(f"# {p.upper()} — {now}\n# {len(uris)}\n")
                for u in uris: f.write(u+"\n")
    print(f"\nOutputs → outputs/")
    print(f"  passing_intranet_configs.txt      ({len(results)})")
    print(f"  ir_exit_configs.txt               ({len(ir_r)})")
    print(f"  ir_reality_configs.txt            ({len(real_r)}) ← best DPI resistance")
    print(f"  ir_mobile_exit_configs.txt        ({len(mob_r)})")
    print(f"  armenian_bridge_configs.txt       ({len(am_r)})")
    print(f"  iran_bridge_configs.txt           ({len(ib_r)}) ← bridge-tested")
    print(f"  iran_appearing.txt                ({len(normal)}) ← ≥2/3 APIs confirm IR")
    print(f"  iran_appearing_strict.txt         ({len(strict)}) ← 3/3 APIs confirm IR")
    print(f"  passing_intranet_configs_base64.txt")
    for p in protos:
        n = len(buckets[p])
        if n: print(f"  by_protocol/{p}.txt               ({n})")

def check_minimum(results):
    if len(results) < MIN_PASSING_CONFIGS:
        print(f"\nWARNING: {len(results)} configs < minimum {MIN_PASSING_CONFIGS}. "
              f"Outputs still written.", file=sys.stderr)

# ── Main ──────────────────────────────────────────────────────────────────────
async def main():
    global _SHARED_SESSION
    sep = "="*57
    print(sep)
    print("Iran Intranet Config Collector  v5.1 + multi-API GeoIP patch")
    print(f"TCP={TCP_TIMEOUT}s  workers={MAX_WORKERS}  probe={PROBE_ENABLED}  "
          f"bridge={not SKIP_IRAN_BRIDGE}")
    print(sep)
    t0 = time.monotonic()
    print("\n[0/3] Loading Armenia CIDR blocks …")
    _get_armenia_networks()
    print("\n[1/3] Collecting configs …")
    uris = await collect_all()
    
    async with aiohttp.ClientSession(headers=HEADERS) as sess:
        _SHARED_SESSION = sess
        print(f"\n[2/3] Verifying {len(uris)} configs (multi-API GeoIP enabled) …")
        results = await verify_configs(uris)
        
    check_minimum(results)
    print("\n[3/3] Writing outputs …")
    write_outputs(results)
    print(f"\n{sep}")
    print(f"Done in {time.monotonic()-t0:.0f}s — {len(results)} configs.")
    print(sep)

if __name__ == "__main__":
    asyncio.run(main())
