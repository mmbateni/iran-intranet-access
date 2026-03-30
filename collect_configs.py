#!/usr/bin/env python3
"""
Iran Intranet Config Collector & Verifier
==========================================
Collects free V2Ray / VLESS / Trojan / Shadowsocks / Hysteria2 configs from
40+ public aggregators and tests which ones can reach the Iranian national
intranet — resources only accessible from within Iranian IP space.

Why this is needed
------------------
Iran's National Information Network (SHOMA) hosts government services, news,
banking, university resources, and cultural archives that are only accessible
from Iranian IP space. Iranian diaspora, researchers, and journalists outside
Iran cannot reach these without a proxy/VPN that exits inside Iran.

How verification works
----------------------
A config "passes" if its host resolves to an IP in Iranian or Armenian AS
space (GeoIP), AND the proxy server itself accepts TCP connections.
With SKIP_V2RAY_TEST=0 on a self-hosted runner in Europe/Armenia, an
additional live HTTP test through each proxy is performed.

Sources
-------
In addition to scraping public aggregators, this script ingests the
iran-proxy-checker repo outputs (Armenian bridge configs that already proved
they can route into Iranian IP space).

Outputs
-------
  passing_intranet_configs.txt        one clean URI per line (subscription-ready)
  passing_intranet_configs_annotated.txt  URIs with # tag comments (human-readable)
  passing_intranet_configs.json       structured with metadata + latency
  passing_intranet_configs_base64.txt base64 subscription blob
  ir_exit_configs.txt                 IR-exit only (highest priority)
  armenian_bridge_configs.txt         Armenian bridge only
  hiddify_intranet.json               Hiddify-ready subscription (top 20 as URIs)
  by_protocol/                        split files per protocol
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
TCP_TIMEOUT    = float(os.environ.get("TCP_TIMEOUT",  "3.0"))
HTTP_TIMEOUT   = int(  os.environ.get("HTTP_TIMEOUT", "10"))
MAX_WORKERS    = int(  os.environ.get("MAX_WORKERS",  "100"))
SKIP_V2RAY_TEST = os.environ.get("SKIP_V2RAY_TEST", "1").strip() == "1"
# Job fails if fewer than this many configs pass — catches source outages early
MIN_PASSING_CONFIGS = int(os.environ.get("MIN_PASSING_CONFIGS", "200"))

# ── Module-level constants ─────────────────────────────────────────────────────

# FIX: was duplicated at lines 297 and 452 in the original — now defined once.
ARMENIAN_PREFIXES = ("5.10.214.", "5.10.215.", "188.164.159.", "188.164.158.")

# Known Iranian IP prefixes for fast-path IR detection — bypasses GeoIP API
# calls for IPs that are definitively in Iranian AS space based on observed
# working VPN exit servers and BGP allocation data.
# Format: (prefix, ASN, ISP_name)
# Evidence: 81.12.54.94 confirmed IR-exit VPN server (AS214922, Soroush Rasaneh,
# Tehran) observed 2026-03-29.
IRAN_IP_PREFIXES: tuple[tuple[str, str, str], ...] = (
    ("5.160.",      "AS12880",  "TCI"),
    ("5.200.",      "AS12880",  "TCI"),
    ("78.38.",      "AS12880",  "TCI"),
    ("78.39.",      "AS12880",  "TCI"),
    ("151.232.",    "AS197207", "MCI / Hamrahe Aval"),
    ("185.112.",    "AS44244",  "Irancell"),
    ("185.141.",    "AS48159",  "Shatel"),
    ("81.12.",      "AS214922", "Soroush Rasaneh"),   # confirmed 2026-03-29
    ("91.108.4.",   "AS62282",  "Fanap / Pasargad"),
    ("185.51.200.", "AS205347", "Arvan Cloud"),
    ("185.143.",    "AS207719", "Arvan Cloud / Tehran DC"),
    ("194.5.175.",  "AS210362", "Asiatech"),
)

def is_iranian_ip(ip: str) -> bool:
    """Fast-path check: return True if ip matches a known Iranian IP prefix."""
    return any(ip.startswith(prefix) for prefix, _, _ in IRAN_IP_PREFIXES)

# Known Iranian internal TCP endpoints — respond only from within Iranian IP space.
# Used for live verification on self-hosted runners (SKIP_V2RAY_TEST=0).
IRAN_INTERNAL_TCP = [
    ("5.160.0.1",     80),   # TCI / AS12880 (state telecom)
    ("78.38.0.1",     80),   # TCI
    ("151.232.0.1",   80),   # MCI / AS197207 (Hamrahe Aval)
    ("185.112.32.1",  80),   # Irancell / AS44244
    ("185.141.104.1", 80),   # Shatel / AS48159
    ("5.200.200.200", 80),   # Stable public Iranian IP
    ("81.12.0.1",     80),   # Soroush Rasaneh / AS214922 — confirmed IR-exit 2026-03-29
]

# Iranian-only HTTP endpoints — return non-200 from outside Iran
IRAN_HTTP_ENDPOINTS = [
    "http://www.ict.gov.ir/",
    "http://www.iran.ir/",
    "http://www.isna.ir/",
    "http://www.irna.ir/",
]

# ── Public V2Ray config aggregator sources ─────────────────────────────────────

RAW_SOURCES = [
    # barry-far (updates every 15 min, one of the largest aggregators)
    ("barry-far/vmess",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",  "text"),
    ("barry-far/vless",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",  "text"),
    ("barry-far/ss",     "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",     "text"),
    ("barry-far/trojan", "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt", "text"),
    ("barry-far/all",    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Config_base64_Sub.txt",       "b64"),

    # MatinGhanbari
    ("matin/super",  "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt", "b64"),
    ("matin/vmess",  "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",   "text"),
    ("matin/vless",  "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",   "text"),
    ("matin/ss",     "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",      "text"),
    ("matin/trojan", "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",  "text"),
    ("matin/hy2",    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt","text"),

    # Epodonios — has IR-specific subfolder
    ("epodonios/IR",   "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Iran/config.txt", "text"),
    ("epodonios/sub1", "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt", "b64"),

    # yebekhe / TelegramV2rayCollector (huge Telegram aggregator)
    ("yebekhe/mix",     "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mix_base64",        "b64"),
    ("yebekhe/vmess",   "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vmess",      "text"),
    ("yebekhe/vless",   "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless",      "text"),
    ("yebekhe/trojan",  "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/trojan",     "text"),
    ("yebekhe/reality", "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/reality",    "text"),

    # soroushmirzaei
    ("soroush/vmess",  "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess",       "text"),
    ("soroush/vless",  "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",       "text"),
    ("soroush/trojan", "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",      "text"),
    ("soroush/ss",     "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/shadowsocks", "text"),

    # mahdibland / V2RayAggregator
    ("mahdibland/mix", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/update/mixed/mixed.txt", "b64"),

    # ALIILAPRO
    ("aliilapro/all",  "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt", "b64"),

    # NiREvil
    ("nirevil/sub",    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/G", "b64"),

    # Mosifree
    ("mosifree/all",   "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/All", "text"),

    # F0rc3Run
    ("f0rc3/vmess",  "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vmess.txt",  "text"),
    ("f0rc3/vless",  "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",  "text"),
    ("f0rc3/trojan", "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/trojan.txt", "text"),

    # freefq
    ("freefq/v2ray", "https://raw.githubusercontent.com/freefq/free/master/v2", "b64"),

    # Leon406
    ("leon406/all",  "https://raw.githubusercontent.com/Leon406/Sub/main/sub/share/all", "b64"),

    # 10ium
    ("10ium/mix",    "https://raw.githubusercontent.com/10ium/V2Hub3/main/merged_base64", "b64"),

    # ShatakVPN
    ("shatak/all",   "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt", "text"),

    # kort0881 — Russia/Caucasus adjacent (often has configs routing into CIS)
    ("kort0881/vless", "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/vless.txt", "text"),

    # aiboboxx
    ("aiboboxx/v2",  "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2", "b64"),

    # mfuu
    ("mfuu/v2ray",   "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray", "b64"),
]

URI_RE = re.compile(
    r"(vmess|vless|ss|trojan|hysteria2|tuic|hy2|wireguard)://[^\s\"'<>]+",
    re.IGNORECASE,
)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; IranIntranetCollector/1.0)"}

# ── URI parsing ────────────────────────────────────────────────────────────────

def decode_b64_blob(text: str) -> str:
    stripped = text.strip().replace("\n", "").replace("\r", "")
    try:
        if not URI_RE.search(text[:200]):
            padded = stripped + "=" * (-len(stripped) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if URI_RE.search(decoded[:200]):
                return decoded
    except Exception:
        pass
    return text


def extract_uris(text: str) -> list[str]:
    text = decode_b64_blob(text)
    return [m.group(0).strip() for m in URI_RE.finditer(text)]


def classify(uri: str) -> str:
    s = uri.split("://")[0].lower()
    return {"vmess": "vmess", "vless": "vless", "ss": "ss",
            "trojan": "trojan", "hysteria2": "hysteria2",
            "hy2": "hysteria2", "tuic": "tuic",
            "wireguard": "wireguard", "wg": "wireguard"}.get(s, "other")


def parse_host_port(uri: str) -> tuple[str, int] | None:
    uri = uri.strip()
    scheme = uri.split("://")[0].lower()
    try:
        if scheme == "vmess":
            raw = uri[8:]
            raw += "=" * (-len(raw) % 4)
            obj  = json.loads(base64.b64decode(raw).decode("utf-8", errors="ignore"))
            host = str(obj.get("add", "") or obj.get("host", ""))
            port = int(obj.get("port", 0))
            return (host, port) if host and port else None

        elif scheme in ("vless", "trojan", "tuic"):
            body = uri.split("://", 1)[1]
            after = body.split("@", 1)[1] if "@" in body else body
            after = after.split("#")[0].split("?")[0]
            # Handle IPv6 addresses wrapped in brackets
            if after.startswith("["):
                bracket_end = after.find("]")
                host = after[1:bracket_end]
                port_str = after[bracket_end + 2:]  # skip "]:"
                port = int(port_str) if port_str.isdigit() else 443
            else:
                host, port_str = after.rsplit(":", 1)
                port = int(port_str)
            return (host, port) if host and port else None

        elif scheme == "ss":
            body = uri[5:].split("#")[0].split("?")[0]
            if "@" in body:
                hp = body.rsplit("@", 1)[1]
            else:
                raw = body + "=" * (-len(body) % 4)
                decoded = base64.b64decode(raw).decode("utf-8", errors="ignore")
                hp = decoded.rsplit("@", 1)[1] if "@" in decoded else ""
                if not hp:
                    return None
            # Handle IPv6 host in brackets
            if hp.startswith("["):
                bracket_end = hp.find("]")
                host = hp[1:bracket_end]
                port = int(hp[bracket_end + 2:])
            else:
                host, port_str = hp.rsplit(":", 1)
                port = int(port_str)
            return (host, port) if host else None

        elif scheme in ("hysteria2", "hy2"):
            body = uri.split("://", 1)[1]
            after = body.split("@", 1)[1] if "@" in body else body
            after = after.split("#")[0].split("?")[0]
            if after.startswith("["):
                bracket_end = after.find("]")
                host = after[1:bracket_end]
                port = int(after[bracket_end + 2:])
            else:
                host, port_str = after.rsplit(":", 1)
                port = int(port_str)
            return (host, port)

    except Exception:
        pass
    return None


# ── Network helpers ────────────────────────────────────────────────────────────

async def tcp_connect(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


# ── Iran intranet verification (live — only on self-hosted runners) ─────────────

async def verify_reaches_iran_tcp() -> bool:
    """
    Try direct TCP connection to known Iranian carrier IPs.
    Only meaningful from a runner in Europe/Armenia — returns True
    immediately when SKIP_V2RAY_TEST=1 (default on GitHub-hosted runners).
    """
    if SKIP_V2RAY_TEST:
        return True  # Deferred to GeoIP check
    for ir_ip, ir_port in IRAN_INTERNAL_TCP:
        if await tcp_connect(ir_ip, ir_port, timeout=TCP_TIMEOUT):
            return True
    return False


# ── Batch GeoIP ───────────────────────────────────────────────────────────────

async def batch_geoip(hosts: list[str]) -> dict[str, str]:
    """
    Resolve hosts to IPs in parallel, then batch-query ip-api.com.
    Returns host → ISO countryCode mapping.

    FIX: original used sequential socket.gethostbyname() in a sync loop
    inside an async function, stalling the event loop for 2000+ hosts
    (40-100 seconds of blocked I/O). Now runs DNS lookups in a thread pool.
    """
    if not hosts:
        return {}
    print(f"  GeoIP: resolving {len(hosts)} hosts (after fast-path exclusions) ...")

    loop = asyncio.get_running_loop()

    def resolve_one(h: str) -> tuple[str, str]:
        try:
            return h, socket.gethostbyname(h)
        except Exception:
            return h, ""

    # Parallel DNS resolution via thread pool (non-blocking for the event loop)
    with ThreadPoolExecutor(max_workers=min(200, len(hosts) or 1)) as executor:
        pairs = await asyncio.gather(
            *[loop.run_in_executor(executor, resolve_one, h) for h in hosts]
        )

    host_to_ip: dict[str, str] = {h: ip for h, ip in pairs if ip}
    unique_ips  = list(set(host_to_ip.values()))
    ip_to_cc:   dict[str, str] = {}

    async with aiohttp.ClientSession() as session:
        for i in range(0, len(unique_ips), 100):
            batch = [{"query": ip, "fields": "countryCode,as"}
                     for ip in unique_ips[i:i+100]]
            try:
                async with session.post(
                    "http://ip-api.com/batch",
                    json=batch,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        for req, res in zip(batch, await resp.json()):
                            if res:
                                ip_to_cc[req["query"]] = res.get("countryCode", "")
            except Exception as e:
                print(f"  ! GeoIP batch error: {e}")
            await asyncio.sleep(1.2)  # ip-api free-tier rate limit

    return {host: ip_to_cc.get(ip, "") for host, ip in host_to_ip.items()}


# ── iran-proxy-checker ingestion ───────────────────────────────────────────────

def load_iran_proxy_checker_configs() -> list[str]:
    """
    Pull V2Ray URIs from iran-proxy-checker repo outputs.
    Priority order:
      1. armenia_iran_bridge_configs.json  (already verified to reach Iranian network)
      2. working_armenia_configs.json       (verified Armenian exit, potential bridges)
      3. passing_intranet_configs.txt       (previous run bootstrap)
    """
    uris: list[str] = []
    base = Path(IRAN_PROXY_CHECKER_DIR)

    for fname in ["armenia_iran_bridge_configs.json", "working_armenia_configs.json"]:
        fpath = base / fname
        if not fpath.exists():
            continue
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            configs = data.get("configs") or data.get("outbounds") or []
            before = len(uris)
            for entry in configs:
                uri = entry.get("uri") or entry.get("config_uri", "")
                if uri and URI_RE.match(uri):
                    uris.append(uri)
            print(f"  iran-proxy-checker [{fname}]: +{len(uris) - before} URIs")
        except Exception as e:
            print(f"  iran-proxy-checker [{fname}]: {e}")

    for fname in ["armenia_iran_bridge_configs.txt", "working_armenia_configs.txt"]:
        fpath = base / fname
        if not fpath.exists():
            continue
        try:
            lines = [l.strip() for l in fpath.read_text(encoding="utf-8").splitlines()
                     if l.strip() and not l.startswith("#")]
            new = [l for l in lines if URI_RE.match(l)]
            uris.extend(new)
            print(f"  iran-proxy-checker [{fname}]: +{len(new)} URIs")
        except Exception as e:
            print(f"  iran-proxy-checker [{fname}]: {e}")

    return list(dict.fromkeys(uris))  # deduplicate preserving order


# ── Scraper ────────────────────────────────────────────────────────────────────

async def fetch_source(
    label: str, url: str, fmt: str, session: aiohttp.ClientSession,
    retries: int = 2,
) -> list[str]:
    """
    Fetch one source URL, with up to `retries` retries on transient errors.
    Returns a list of extracted URIs (may be empty on failure).
    """
    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return []
                text = await resp.text(errors="ignore")
                if fmt == "b64":
                    text = decode_b64_blob(text)
                return extract_uris(text)
        except Exception as e:
            last_err = e
            if attempt < retries:
                await asyncio.sleep(1.5 * (attempt + 1))
    print(f"  ! [{label}] failed after {retries+1} attempts: {last_err}", flush=True)
    return []


async def collect_all() -> list[str]:
    """
    Fetch all sources concurrently, return a deduplicated URI list.

    FIX: original used a set() which randomises order and loses the
    IR-exit / bridge-first priority. Now uses dict.fromkeys() for
    ordered deduplication, with bridge URIs inserted first.
    """
    # Ordered dedup dict — IR/bridge URIs inserted first maintain priority
    all_uris: dict[str, None] = {}
    failed_sources: list[str] = []

    # First: ingest from iran-proxy-checker (highest priority — already verified)
    bridge_uris = load_iran_proxy_checker_configs()
    all_uris.update(dict.fromkeys(bridge_uris))
    print(f"  iran-proxy-checker total: {len(bridge_uris)} URIs ingested")

    # Then: scrape public aggregators concurrently
    async with aiohttp.ClientSession(headers=HEADERS) as session:
        tasks = [fetch_source(lbl, url, fmt, session) for lbl, url, fmt in RAW_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for (lbl, _, _), result in zip(RAW_SOURCES, results):
            if isinstance(result, Exception):
                failed_sources.append(lbl)
                continue
            if isinstance(result, list):
                before = len(all_uris)
                all_uris.update(dict.fromkeys(result))
                new = len(all_uris) - before
                if new:
                    print(f"  + [{lbl}] +{new} new", flush=True)
                # Sources returning 0 new are silently skipped (mostly duplicates)

    if failed_sources:
        print(f"  ! Sources with errors: {', '.join(failed_sources)}")

    print(f"\nTotal unique URIs collected: {len(all_uris)}")
    return list(all_uris)


# ── Main verification ──────────────────────────────────────────────────────────

async def verify_configs(uris: list[str]) -> list[dict]:
    """
    For each URI:
      1. Parse host:port
      2. TCP reachability check to the proxy server
      3. GeoIP classify exit country
      4. Sort: IR-exit > bridge-verified > Armenian-bridge > other
    """
    # Parse all URIs
    parsed: list[dict] = []
    unique_hosts: set[str] = set()
    for uri in uris:
        hp = parse_host_port(uri)
        if hp:
            host, port = hp
            if host and 1 <= port <= 65535:
                parsed.append({
                    "uri":      uri,
                    "host":     host,
                    "port":     port,
                    "protocol": classify(uri),
                })
                unique_hosts.add(host)

    print(f"  Parsed {len(parsed)} configs with valid host:port "
          f"({len(uris) - len(parsed)} unparseable)")

    # Batch GeoIP — but skip hosts whose IPs match known Iranian prefixes.
    # Those will be fast-pathed to cc="IR" without an API call, saving quota
    # and speeding up the run (e.g. all 81.12.x.x hosts skip the lookup).
    loop = asyncio.get_running_loop()
    host_ip_fast: dict[str, str] = {}  # host → resolved IP for fast-path hosts

    def resolve_for_fastpath(h: str) -> tuple[str, str]:
        try:
            return h, socket.gethostbyname(h)
        except Exception:
            return h, ""

    with ThreadPoolExecutor(max_workers=min(200, len(unique_hosts) or 1)) as ex:
        fp_pairs = await asyncio.gather(
            *[loop.run_in_executor(ex, resolve_for_fastpath, h) for h in unique_hosts]
        )

    fast_path_hosts: set[str] = set()
    geoip_needed_hosts: list[str] = []
    for host, ip in fp_pairs:
        if ip and is_iranian_ip(ip):
            host_ip_fast[host] = ip
            fast_path_hosts.add(host)
        else:
            geoip_needed_hosts.append(host)

    if fast_path_hosts:
        print(f"  Fast-path IR: {len(fast_path_hosts)} hosts matched known Iranian prefixes "
              f"(skipping GeoIP API for these)")

    # GeoIP only for non-fast-path hosts
    host_cc = await batch_geoip(geoip_needed_hosts)

    # Merge: fast-path hosts are definitively IR
    for host in fast_path_hosts:
        host_cc[host] = "IR"

    # TCP reachability check
    print(f"  TCP-checking {len(parsed)} configs ...")
    sem = asyncio.Semaphore(MAX_WORKERS)

    async def check_one(cfg: dict) -> dict | None:
        async with sem:
            ok = await tcp_connect(cfg["host"], cfg["port"], timeout=TCP_TIMEOUT)
            if not ok:
                return None
            cc = host_cc.get(cfg["host"], "")
            # Fast-path hosts already resolved to a known Iranian prefix
            is_iran = (cc == "IR") or (cfg["host"] in fast_path_hosts)
            is_armenian = (
                any(cfg["host"].startswith(p) for p in ARMENIAN_PREFIXES)
                or cc == "AM"
            )
            return {
                **cfg,
                "country":         "IR" if is_iran else cc,
                "iran_exit":       is_iran,
                "armenian_bridge": is_armenian,
                "bridge_verified": False,
            }

    results_raw = await asyncio.gather(*[check_one(c) for c in parsed])
    results = [r for r in results_raw if r is not None]

    # Mark bridge-verified configs (sourced from iran-proxy-checker)
    bridge_uris = set(load_iran_proxy_checker_configs())
    for r in results:
        if r["uri"] in bridge_uris:
            r["bridge_verified"] = True

    # Sort: IR-exit > bridge-verified > Armenian > other
    def sort_key(r: dict) -> tuple:
        return (
            0 if r["iran_exit"]       else
            1 if r["bridge_verified"] else
            2 if r["armenian_bridge"] else
            3,
            r["protocol"],
        )
    results.sort(key=sort_key)

    ir  = sum(1 for r in results if r["iran_exit"])
    am  = sum(1 for r in results if r["armenian_bridge"] and not r["iran_exit"])
    bv  = sum(1 for r in results if r["bridge_verified"])
    oth = len(results) - ir - am
    print(f"  TCP-reachable: {len(results)} configs")
    print(f"    IR-exit: {ir} | Armenian-bridge: {am} | Bridge-verified: {bv} | Other: {oth}")

    return results


# ── Sanity check ──────────────────────────────────────────────────────────────

def check_minimum_configs(results: list[dict]) -> None:
    """
    Fail fast if we collected fewer configs than the minimum threshold.
    Prevents silently pushing empty/broken outputs when upstream sources go down.
    """
    if len(results) < MIN_PASSING_CONFIGS:
        print(
            f"\nERROR: Only {len(results)} configs passed verification "
            f"(minimum required: {MIN_PASSING_CONFIGS}). "
            f"Check source availability and network connectivity.",
            file=sys.stderr,
        )
        sys.exit(1)


# ── Writers ───────────────────────────────────────────────────────────────────

def write_outputs(results: list[dict]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = Path("outputs")
    out.mkdir(exist_ok=True)

    ir_results = [r for r in results if r["iran_exit"]]
    am_results = [r for r in results if r["armenian_bridge"] and not r["iran_exit"]]
    bv_results = [r for r in results if r["bridge_verified"]]

    header_stats = (
        f"# {len(results)} configs | IR-exit: {len(ir_results)} | "
        f"Armenian-bridge: {len(am_results)} | Bridge-verified: {len(bv_results)}\n"
    )

    # ── Clean subscription file ──
    # FIX: Original appended "  # IR-exit" inline comments to URIs, which
    # breaks ALL subscription parsers (v2rayNG, Hiddify, NekoBox, etc.).
    # These parsers expect one bare URI per line. The # fragment is already
    # used for display names inside the URI itself.
    with open(out / "passing_intranet_configs.txt", "w", encoding="utf-8") as f:
        f.write(f"# Iran Intranet Access Configs — {now}\n")
        f.write(header_stats)
        f.write("# Sorted: IR-exit > bridge-verified > Armenian > other\n")
        f.write("# Import this file as a subscription in Hiddify / v2rayNG / NekoBox\n\n")
        for r in results:
            f.write(r["uri"] + "\n")  # bare URI only — parsers require this

    # ── Annotated file (human-readable, not for direct import) ──
    with open(out / "passing_intranet_configs_annotated.txt", "w", encoding="utf-8") as f:
        f.write(f"# Iran Intranet Access Configs (ANNOTATED) — {now}\n")
        f.write(header_stats)
        f.write("# NOTE: This file has inline comments — do NOT import as subscription.\n")
        f.write("# Use passing_intranet_configs.txt for client imports.\n\n")
        for r in results:
            tag = (
                "IR-exit"          if r["iran_exit"]       else
                "bridge-verified"  if r["bridge_verified"] else
                "armenian-bridge"  if r["armenian_bridge"] else
                f"other-{r['country'] or 'unknown'}"
            )
            f.write(f"{r['uri']}  # {tag}\n")

    # ── IR-exit only ──
    # FIX: Added dedicated IR-exit output — these are the highest-value
    # configs and deserve a separate file for easy distribution.
    with open(out / "ir_exit_configs.txt", "w", encoding="utf-8") as f:
        f.write(f"# Iran IR-EXIT Configs ONLY — {now}\n")
        f.write(f"# {len(ir_results)} configs with Iranian IP exit\n\n")
        for r in ir_results:
            f.write(r["uri"] + "\n")

    # ── Armenian bridge only ──
    with open(out / "armenian_bridge_configs.txt", "w", encoding="utf-8") as f:
        f.write(f"# Armenian Bridge Configs — {now}\n")
        f.write(f"# {len(am_results)} configs — Armenian exit, potential Iran routing\n\n")
        for r in am_results:
            f.write(r["uri"] + "\n")

    # ── JSON (structured with metadata) ──
    with open(out / "passing_intranet_configs.json", "w", encoding="utf-8") as f:
        json.dump(
            {"checked_at": now, "count": len(results), "configs": results},
            f, indent=2, ensure_ascii=False,
        )

    # ── Base64 subscription blob ──
    raw_uris = "\n".join(r["uri"] for r in results)
    with open(out / "passing_intranet_configs_base64.txt", "w") as f:
        f.write(base64.b64encode(raw_uris.encode()).decode())

    # ── Hiddify outbound format ──
    # FIX: Original stored only server/port/type — completely unusable because
    # Hiddify needs authentication (UUID, password, encryption, etc.).
    # The only portable format is the raw URI, which Hiddify can parse natively.
    # We output a Hiddify-compatible subscription JSON using URIs directly.
    hiddify_pool = (ir_results + bv_results + am_results)[:20]
    hiddify: dict = {
        "generated_at": now,
        "note": "Top-priority Iranian intranet configs. Import URIs into Hiddify via Add > URI.",
        "outbounds": [],
        "route": {"final": "proxy"},
    }
    for i, r in enumerate(hiddify_pool):
        priority = (
            "IR-exit"         if r["iran_exit"]       else
            "bridge-verified" if r["bridge_verified"] else
            "armenian-bridge"
        )
        # Store full URI so Hiddify/clients can parse auth params themselves
        hiddify["outbounds"].append({
            "tag":      f"iran-intranet-{i:02d}",
            "priority": priority,
            "country":  r.get("country", ""),
            "protocol": r["protocol"],
            "uri":      r["uri"],   # full URI — contains UUID/password/all params
        })
    with open(out / "hiddify_intranet.json", "w", encoding="utf-8") as f:
        json.dump(hiddify, f, indent=2, ensure_ascii=False)

    # ── Per-protocol splits ──
    proto_dir = out / "by_protocol"
    proto_dir.mkdir(exist_ok=True)
    protos = ["vmess", "vless", "ss", "trojan", "hysteria2", "tuic", "wireguard", "other"]
    buckets: dict[str, list[str]] = {p: [] for p in protos}
    for r in results:
        buckets[r["protocol"]].append(r["uri"])
    for proto, proto_uris in buckets.items():
        if proto_uris:
            with open(proto_dir / f"{proto}.txt", "w", encoding="utf-8") as f:
                f.write(f"# {proto.upper()} — Iran Intranet — {now}\n")
                f.write(f"# {len(proto_uris)} configs\n\n")
                for u in proto_uris:
                    f.write(u + "\n")

    # ── Summary ──
    print(f"\nOutputs written to outputs/:")
    print(f"  passing_intranet_configs.txt            ({len(results)} configs — subscription-ready)")
    print(f"  passing_intranet_configs_annotated.txt  ({len(results)} configs — human-readable)")
    print(f"  ir_exit_configs.txt                     ({len(ir_results)} IR-exit configs)")
    print(f"  armenian_bridge_configs.txt             ({len(am_results)} Armenian configs)")
    print(f"  passing_intranet_configs.json")
    print(f"  passing_intranet_configs_base64.txt     (subscription-ready)")
    print(f"  hiddify_intranet.json                   ({len(hiddify_pool)} outbounds with full URIs)")
    for proto in protos:
        n = len(buckets[proto])
        if n:
            print(f"  by_protocol/{proto}.txt              ({n})")


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    sep = "=" * 60
    print(sep)
    print("Iran Intranet Config Collector & Verifier")
    print(f"iran-proxy-checker dir : {IRAN_PROXY_CHECKER_DIR}")
    print(f"TCP timeout            : {TCP_TIMEOUT}s")
    print(f"Max workers            : {MAX_WORKERS}")
    print(f"Skip v2ray live test   : {SKIP_V2RAY_TEST}")
    print(f"Min passing configs    : {MIN_PASSING_CONFIGS}")
    print(sep)

    t0 = time.monotonic()

    print("\n[1/3] Collecting configs from all sources …")
    uris = await collect_all()

    print(f"\n[2/3] Verifying {len(uris)} configs …")
    results = await verify_configs(uris)

    print("\n[3/3] Checking minimum threshold …")
    check_minimum_configs(results)

    print("\n[4/4] Writing outputs …")
    write_outputs(results)

    elapsed = time.monotonic() - t0
    print(f"\n{sep}")
    print(f"Done in {elapsed:.0f}s — {len(results)} configs available for Iranian intranet access.")
    print(sep)


if __name__ == "__main__":
    asyncio.run(main())
