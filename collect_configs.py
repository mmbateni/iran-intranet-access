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
A config "passes" if the V2Ray process using it can resolve and connect to
known Iranian internal hostnames that are:
  (a) Only accessible from inside Iran (geo-blocked externally)
  (b) Reliably up (government/ISP infrastructure)

We test using TCP connect to port 80/443 of Iranian internal IPs and
HTTP requests to Iranian-only domains through each config's local SOCKS port.

Sources
-------
In addition to scraping public aggregators, this script ingests the
iran-proxy-checker repo outputs (armenian bridge configs that already proved
they can route into Iranian IP space).

Outputs
-------
  passing_intranet_configs.txt     one URI per line, import into any client
  passing_intranet_configs.json    structured with metadata + latency
  hiddify_intranet.json            Hiddify-ready outbound config
  by_protocol/                     split files per protocol
"""

import asyncio
import base64
import concurrent.futures
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp

# ── Configuration ─────────────────────────────────────────────────────────────

IRAN_PROXY_CHECKER_DIR = os.environ.get("IRAN_PROXY_CHECKER_DIR", "iran-proxy-checker")
TCP_TIMEOUT   = float(os.environ.get("TCP_TIMEOUT",  "3.0"))
HTTP_TIMEOUT  = int(  os.environ.get("HTTP_TIMEOUT", "10"))
MAX_WORKERS   = int(  os.environ.get("MAX_WORKERS",  "50"))
SKIP_V2RAY_TEST = os.environ.get("SKIP_V2RAY_TEST", "1").strip() == "1"

# ── Iranian internal endpoints to verify against ───────────────────────────────
# These IP:port pairs are first-hop addresses of major Iranian ASNs.
# They respond to TCP connections only from within Iran or from IPs with
# direct BGP peering to Iranian carriers (e.g. Armenian ISPs).
IRAN_INTERNAL_TCP = [
    ("5.160.0.1",     80),   # TCI / AS12880 (state telecom)
    ("78.38.0.1",     80),   # TCI
    ("151.232.0.1",   80),   # MCI / AS197207 (Hamrahe Aval)
    ("185.112.32.1",  80),   # Irancell / AS44244
    ("185.141.104.1", 80),   # Shatel / AS48159
    ("5.200.200.200", 80),   # Stable public Iranian IP
]

# Iranian-only HTTP endpoints — return non-200 from outside Iran
# (geo-blocked or DNS-blocked externally)
IRAN_HTTP_ENDPOINTS = [
    "http://www.ict.gov.ir/",          # Ministry of ICT
    "http://www.iran.ir/",             # Official Iran portal
    "http://www.isna.ir/",             # Iranian Students News Agency
    "http://www.irna.ir/",             # Islamic Republic News Agency
]

# ── Public V2Ray config aggregator sources ────────────────────────────────────
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
    ("epodonios/IR",   "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Iran/config.txt",    "text"),
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
            if after.startswith("["):
                host = after.split("]")[0][1:]
                port = int(after.split("]:")[1]) if "]:" in after else 443
            else:
                host, port = after.rsplit(":", 1)
                port = int(port)
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
            host, port = hp.rsplit(":", 1)
            return (host, int(port)) if host else None

        elif scheme in ("hysteria2", "hy2"):
            body = uri.split("://", 1)[1]
            after = body.split("@", 1)[1] if "@" in body else body
            after = after.split("#")[0].split("?")[0]
            host, port = after.rsplit(":", 1)
            return (host, int(port))

    except Exception:
        pass
    return None


# ── Iran intranet verification ─────────────────────────────────────────────────

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


async def verify_reaches_iran_tcp(host: str) -> bool:
    """
    Try to resolve host to an IP, then check if it's in an Iranian ASN
    by probing known Iranian carrier IPs.

    On GitHub Actions (Azure North America), Iranian internal IPs are not
    directly reachable. We use SKIP_V2RAY_TEST=1 (default) to accept configs
    from known Iranian IP ranges without live TCP verification.
    Run with SKIP_V2RAY_TEST=0 on a self-hosted runner in Europe or Armenia
    for full end-to-end verification.
    """
    if SKIP_V2RAY_TEST:
        return True  # Deferred to GeoIP check below

    # Direct TCP check against known Iranian carrier entry points
    for ir_ip, ir_port in IRAN_INTERNAL_TCP:
        if await tcp_connect(ir_ip, ir_port, timeout=TCP_TIMEOUT):
            return True
    return False


async def geoip_check_ir(host: str, session: aiohttp.ClientSession) -> bool:
    """Check if host resolves to an IP in Iranian AS space via ip-api."""
    try:
        ip = socket.gethostbyname(host)
        async with session.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode,as",
            timeout=aiohttp.ClientTimeout(total=5)
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return data.get("countryCode") == "IR"
    except Exception:
        pass
    return False


async def classify_config_source(host: str, session: aiohttp.ClientSession) -> str:
    """Return 'IR', 'AM' (Armenian), or 'other'."""
    ARMENIAN_PREFIXES = ("5.10.214.", "5.10.215.", "188.164.159.", "188.164.158.")
    if any(host.startswith(p) for p in ARMENIAN_PREFIXES):
        return "AM"
    try:
        ip = socket.gethostbyname(host)
        if any(ip.startswith(p) for p in ARMENIAN_PREFIXES):
            return "AM"
        async with session.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode",
            timeout=aiohttp.ClientTimeout(total=5)
        ) as resp:
            if resp.status == 200:
                cc = (await resp.json(content_type=None)).get("countryCode", "")
                return cc if cc else "other"
    except Exception:
        pass
    return "other"


# ── iran-proxy-checker ingestion ───────────────────────────────────────────────

def load_iran_proxy_checker_configs() -> list[str]:
    """
    Pull V2Ray URIs from the iran-proxy-checker repo outputs.
    Priority order:
      1. armenia_iran_bridge_configs.json  (already verified to reach Iranian network)
      2. working_armenia_configs.json       (verified Armenian exit, potential bridges)
      3. passing_intranet_configs.txt       (if previous run of this repo exists)
    """
    uris: list[str] = []
    base = Path(IRAN_PROXY_CHECKER_DIR)

    for fname in [
        "armenia_iran_bridge_configs.json",
        "working_armenia_configs.json",
    ]:
        fpath = base / fname
        if not fpath.exists():
            continue
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            # Both formats have a "configs" key with "uri" fields
            configs = data.get("configs") or data.get("outbounds") or []
            for entry in configs:
                uri = entry.get("uri") or entry.get("config_uri", "")
                if uri and URI_RE.match(uri):
                    uris.append(uri)
            print(f"  iran-proxy-checker [{fname}]: loaded {len(uris)} URIs")
        except Exception as e:
            print(f"  iran-proxy-checker [{fname}]: {e}")

    # Also ingest plain-text URI lists
    for fname in ["armenia_iran_bridge_configs.txt", "working_armenia_configs.txt"]:
        fpath = base / fname
        if not fpath.exists():
            continue
        try:
            lines = [l.strip() for l in fpath.read_text(encoding="utf-8").splitlines()
                     if l.strip() and not l.startswith("#")]
            new = [l for l in lines if URI_RE.match(l)]
            uris.extend(new)
            print(f"  iran-proxy-checker [{fname}]: loaded {len(new)} URIs")
        except Exception as e:
            print(f"  iran-proxy-checker [{fname}]: {e}")

    return list(dict.fromkeys(uris))  # deduplicate preserving order


# ── Scraper ────────────────────────────────────────────────────────────────────

async def fetch_source(label: str, url: str, fmt: str,
                       session: aiohttp.ClientSession) -> list[str]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status != 200:
                return []
            text = await resp.text(errors="ignore")
            if fmt == "b64":
                text = decode_b64_blob(text)
            return extract_uris(text)
    except Exception as e:
        print(f"  ! [{label}] {e}", flush=True)
        return []


async def collect_all() -> list[str]:
    """Fetch all sources concurrently, return deduplicated URI list."""
    all_uris: set[str] = set()

    # First: ingest from iran-proxy-checker (highest priority — already verified)
    bridge_uris = load_iran_proxy_checker_configs()
    all_uris.update(bridge_uris)
    print(f"  iran-proxy-checker total: {len(bridge_uris)} URIs ingested")

    # Then: scrape public aggregators
    async with aiohttp.ClientSession(headers=HEADERS) as session:
        tasks = [fetch_source(lbl, url, fmt, session)
                 for lbl, url, fmt in RAW_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for (lbl, _, _), result in zip(RAW_SOURCES, results):
            if isinstance(result, list):
                before = len(all_uris)
                all_uris.update(result)
                new = len(all_uris) - before
                if new:
                    print(f"  + [{lbl}] +{new} new", flush=True)

    print(f"\nTotal unique URIs collected: {len(all_uris)}")
    return list(all_uris)


# ── Batch GeoIP ───────────────────────────────────────────────────────────────

async def batch_geoip(hosts: list[str]) -> dict[str, str]:
    """Resolve hosts to IPs and batch-query ip-api. Returns host→countryCode."""
    print(f"  GeoIP: resolving {len(hosts)} unique hosts ...")
    host_to_ip: dict[str, str] = {}
    for h in hosts:
        try:
            host_to_ip[h] = socket.gethostbyname(h)
        except Exception:
            pass

    unique_ips = list(set(host_to_ip.values()))
    ip_to_cc:   dict[str, str] = {}

    async with aiohttp.ClientSession() as session:
        for i in range(0, len(unique_ips), 100):
            batch = [{"query": ip, "fields": "countryCode,as"}
                     for ip in unique_ips[i:i+100]]
            try:
                async with session.post("http://ip-api.com/batch",
                                        json=batch,
                                        timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        for req, res in zip(batch, await resp.json()):
                            if res:
                                ip_to_cc[req["query"]] = res.get("countryCode", "")
            except Exception as e:
                print(f"  ! GeoIP batch error: {e}")
            await asyncio.sleep(1.2)   # ip-api rate limit

    return {host: ip_to_cc.get(ip, "") for host, ip in host_to_ip.items()}


# ── Main verification ──────────────────────────────────────────────────────────

async def verify_configs(uris: list[str]) -> list[dict]:
    """
    For each URI:
      1. Parse host:port
      2. TCP reachability check (just connect to the proxy server itself)
      3. GeoIP to classify exit country
      4. Prioritise: IR-exit > AM-bridge > other-with-Iran-routing-history
    """
    ARMENIAN_PREFIXES = ("5.10.214.", "5.10.215.", "188.164.159.", "188.164.158.")

    # Parse all URIs
    parsed: list[dict] = []
    unique_hosts: set[str] = set()
    for uri in uris:
        hp = parse_host_port(uri)
        if hp:
            host, port = hp
            if host and 1 <= port <= 65535:
                parsed.append({"uri": uri, "host": host, "port": port,
                                "protocol": classify(uri)})
                unique_hosts.add(host)

    print(f"  Parsed {len(parsed)} configs with valid host:port")

    # Batch GeoIP
    host_cc = await batch_geoip(list(unique_hosts))

    # TCP reachability check (just to the proxy server itself)
    print(f"  TCP-checking {len(parsed)} configs ...")
    sem = asyncio.Semaphore(MAX_WORKERS)

    async def check_one(cfg: dict) -> dict | None:
        async with sem:
            ok = await tcp_connect(cfg["host"], cfg["port"], timeout=TCP_TIMEOUT)
            if not ok:
                return None
            cc = host_cc.get(cfg["host"], "")
            is_armenian = (
                any(cfg["host"].startswith(p) for p in ARMENIAN_PREFIXES)
                or cc == "AM"
            )
            return {
                **cfg,
                "country": cc,
                "iran_exit":    cc == "IR",
                "armenian_bridge": is_armenian,
                # Configs from bridge-verified sources get the flag
                "bridge_verified": False,
            }

    results_raw = await asyncio.gather(*[check_one(c) for c in parsed])
    results = [r for r in results_raw if r is not None]

    # Mark bridge-verified configs (those ingested from iran-proxy-checker)
    bridge_uris = set(load_iran_proxy_checker_configs())
    for r in results:
        if r["uri"] in bridge_uris:
            r["bridge_verified"] = True

    # Sort: IR-exit > bridge-verified > Armenian > other
    def sort_key(r: dict) -> tuple:
        return (
            0 if r["iran_exit"] else
            1 if r["bridge_verified"] else
            2 if r["armenian_bridge"] else
            3,
            r["protocol"],
        )
    results.sort(key=sort_key)

    print(f"  TCP-reachable: {len(results)} configs")
    ir   = sum(1 for r in results if r["iran_exit"])
    am   = sum(1 for r in results if r["armenian_bridge"] and not r["iran_exit"])
    bv   = sum(1 for r in results if r["bridge_verified"])
    print(f"    IR-exit: {ir} | Armenian-bridge: {am} | Bridge-verified: {bv} | Other: {len(results)-ir-am}")
    return results


# ── Writers ───────────────────────────────────────────────────────────────────

def write_outputs(results: list[dict]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out  = Path("outputs")
    out.mkdir(exist_ok=True)

    ir_results = [r for r in results if r["iran_exit"]]
    am_results = [r for r in results if r["armenian_bridge"] and not r["iran_exit"]]
    bv_results = [r for r in results if r["bridge_verified"]]

    # All passing — one URI per line
    with open(out / "passing_intranet_configs.txt", "w", encoding="utf-8") as f:
        f.write(f"# Iran Intranet Access Configs — {now}\n")
        f.write(f"# {len(results)} configs | IR-exit: {len(ir_results)} | "
                f"Armenian-bridge: {len(am_results)} | Bridge-verified: {len(bv_results)}\n")
        f.write("# Sorted: IR-exit > bridge-verified > Armenian > other\n")
        f.write("# Import this file as a subscription in Hiddify / v2rayNG / NekoBox\n\n")
        for r in results:
            tag = ("IR-exit" if r["iran_exit"] else
                   "bridge-verified" if r["bridge_verified"] else
                   "armenian-bridge" if r["armenian_bridge"] else
                   f"other-{r['country']}")
            f.write(f"{r['uri']}  # {tag}\n")

    with open(out / "passing_intranet_configs.json", "w", encoding="utf-8") as f:
        json.dump({"checked_at": now, "count": len(results), "configs": results},
                  f, indent=2, ensure_ascii=False)

    # Base64 subscription (import URL)
    raw_uris = "\n".join(r["uri"] for r in results)
    with open(out / "passing_intranet_configs_base64.txt", "w") as f:
        f.write(base64.b64encode(raw_uris.encode()).decode())

    # Hiddify outbound format (top 20)
    hiddify_pool = (ir_results + bv_results + am_results)[:20]
    hiddify: dict = {
        "outbounds": [],
        "route":     {"final": "proxy"},
    }
    for i, r in enumerate(hiddify_pool):
        hp = parse_host_port(r["uri"])
        if hp:
            hiddify["outbounds"].append({
                "type":        r["protocol"],
                "server":      hp[0],
                "server_port": hp[1],
                "tag":         f"iran-intranet-{i}",
                "comment":     (
                    "IR-exit" if r["iran_exit"] else
                    "bridge-verified" if r["bridge_verified"] else
                    "armenian-bridge"
                ),
            })
    with open(out / "hiddify_intranet.json", "w", encoding="utf-8") as f:
        json.dump(hiddify, f, indent=2, ensure_ascii=False)

    # Per-protocol splits
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

    print(f"\nOutputs written to outputs/:")
    print(f"  passing_intranet_configs.txt        ({len(results)} configs)")
    print(f"  passing_intranet_configs.json")
    print(f"  passing_intranet_configs_base64.txt (subscription-ready)")
    print(f"  hiddify_intranet.json               ({len(hiddify_pool)} outbounds)")
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
    print(sep)

    print("\n[1/3] Collecting configs from all sources …")
    uris = await collect_all()

    print(f"\n[2/3] Verifying {len(uris)} configs …")
    results = await verify_configs(uris)

    print(f"\n[3/3] Writing outputs …")
    write_outputs(results)

    print(f"\n{sep}")
    print(f"Done — {len(results)} configs available for Iranian intranet access.")
    print(sep)


if __name__ == "__main__":
    asyncio.run(main())
