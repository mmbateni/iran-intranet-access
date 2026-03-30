# Iran Intranet Config Collector

**"اینترنت نمی‌میرد" — The Internet Never Dies**

Collects and verifies proxy/VPN configs that **exit inside Iranian IP space**, enabling researchers, journalists, and the Iranian diaspora outside Iran to reach the National Information Network (SHOMA) — government services, banking, universities, and cultural archives that are only accessible from within Iranian AS space.

> **Direction A only** — this project helps people *outside* Iran reach SHOMA resources.
> For Direction B (helping people *inside* Iran reach the global internet during shutdowns), see [JavidNet](https://github.com/Iman/javidnet).

---

## How it works

Every run:
1. Pulls verified bridge configs from a companion `iran-proxy-checker` repo (bootstrap)
2. Scrapes 40+ public V2Ray / VLESS / Trojan / Shadowsocks / Hysteria2 aggregators
3. Fast-path classifies hosts against a registry of 60+ known Iranian IP prefixes (no API call needed for TCI, MCI, Irancell, Arvan Cloud, etc.)
4. Runs GeoIP + ASN lookup on the remainder via ip-api.com
5. TCP-checks every reachable proxy
6. Sorts results: **IR-mobile-exit → IR-exit → bridge-verified → Armenian → other**
7. Within each tier, prefers harder-to-block protocols: TUIC > Hysteria2 > VLESS > Trojan > VMess > SS
8. Commits fresh output files to this repo twice daily

---

## Setup (fork this repo)

1. **Fork** this repository
2. Set repository variable `IRAN_PROXY_CHECKER_REPO` → `your-username/iran-proxy-checker`
   *(Settings → Variables → Actions → New repository variable)*
3. If `iran-proxy-checker` is private, add secret `IRAN_PROXY_TOKEN` → a PAT with `repo` read scope
4. Enable Actions → the workflow runs automatically twice a day

No secrets are required if both repos are public.

---

## Output files explained

All files are written to `outputs/` and committed after every run.

| File | What it is | Use it for |
|---|---|---|
| `passing_intranet_configs.txt` | All verified configs — bare URIs, one per line | Full subscription import |
| **`ir_exit_configs.txt`** | **Configs confirmed to exit inside Iranian IP space** | **Start here** |
| `ir_mobile_exit_configs.txt` | MCI / Irancell / Rightel exits — last operators to go offline during shutdowns | Backup when others fail |
| `armenian_bridge_configs.txt` | Armenian corridor bridges (South Caucasus route into Iran) | Last resort |
| `passing_intranet_configs_base64.txt` | Base64-encoded subscription blob | Clients that require base64 |
| `by_protocol/` | Per-protocol splits: `vless.txt`, `vmess.txt`, `hysteria2.txt`, etc. | Protocol-specific clients |

> The other configs in `passing_intranet_configs.txt` beyond `ir_exit_configs.txt` are reachable proxies that couldn't be GeoIP-confirmed as IR exits — they may still work but aren't verified.

---

## Next steps after setup

### 1 — Get your subscription URL

Replace `YOUR-USERNAME` and `YOUR-REPO` with your actual values:

```
# Recommended — IR-confirmed exits only
https://raw.githubusercontent.com/YOUR-USERNAME/YOUR-REPO/main/outputs/ir_exit_configs.txt

# All verified configs
https://raw.githubusercontent.com/YOUR-USERNAME/YOUR-REPO/main/outputs/passing_intranet_configs.txt

# Base64 blob (some clients prefer this)
https://raw.githubusercontent.com/YOUR-USERNAME/YOUR-REPO/main/outputs/passing_intranet_configs_base64.txt
```

The workflow re-runs twice daily and commits fresh results, so this URL always stays current.

### 2 — Import into a client

**Hiddify** (Windows / Mac / Linux / Android / iOS) — recommended

1. Download from [hiddify.com](https://hiddify.com)
2. Tap `+` → Add from URL → paste your `ir_exit_configs.txt` raw URL
3. All configs import as separate profiles

**v2rayNG** (Android)

1. ☰ → Subscription group → Add → paste the URL
2. Update → select a config → Connect

**NekoBox** (Windows / Linux)

1. Group → Add subscription → paste URL

**Xray / Xray-core**

Import the subscription URL directly or paste individual URIs from `ir_exit_configs.txt`.

### 3 — Verify you're actually inside Iran

Once connected, open these URLs in a browser — they only respond from Iranian IP space:

| URL | What it is |
|---|---|
| `http://www.ict.gov.ir/` | Ministry of ICT |
| `http://www.bmi.ir/` | Bank Melli Iran |
| `http://www.isna.ir/` | ISNA news agency |
| `https://my.gov.ir/` | National e-government portal |

Cross-check your exit IP at `http://ip-api.com/` — the `countryCode` field should show `IR`.

### 4 — Find your best configs

Not all verified configs will connect from your location. In Hiddify:

- Run **Real Delay** test (⚡ button) — measures actual end-to-end latency
- Sort by latency, disable anything over ~2,000 ms
- Keep your top 5–10 for daily use

Configs routing through **Arvan Cloud** (`185.143.x.x`, AS207719) and domains like `snapp.ir` / `snapp.doctor` use major Iranian infrastructure as cover and tend to be the most stable.

Configs with malformed URIs (e.g. repeated `---@channel---@channel` fragments) will fail — skip those.

### 5 — Keep it updated

The workflow runs at **03:30 UTC** (08:00 Tehran) and **13:30 UTC** (18:00 Tehran) every day. Refresh the subscription in your client to pick up new configs as old ones go offline:

- **Hiddify**: pull-to-refresh on the subscription
- **v2rayNG**: Subscription → Update subscription

---

## Network context

Iran's internet is controlled through a small number of state-linked operators:

| Operator | ASN | Role | Shutdown resilience |
|---|---|---|---|
| TCI / DCI | AS12880, AS58224 | Backbone | First to go — lost 810 prefixes in Jan 2026 shutdown |
| MCI / Hamrahe Aval | AS197207 | Mobile (~66% market) | High — 689 routes survived Jan 2026 |
| Irancell | AS44244 | Mobile (~10% market) | High — 368 routes survived Jan 2026 |
| Rightel | AS57218 | Mobile | Medium |
| Shatel / TIC | AS48159 | Fixed ISP | Medium |
| Arvan Cloud | AS205347, AS207719 | Iranian CDN | Used by gov/banking — usually stays up |

All international gateways are controlled by the state via TIC (AS48159), enabling complete shutdowns. During the January 2026 shutdown, 2,375 BGP prefixes (26% of Iran's address space) were withdrawn — but mobile carriers and Arvan Cloud remained partially reachable.

---

## Protocol notes

Iranian DPI (deep packet inspection) varies by operator. Protocol resilience, best to worst:

| Protocol | Notes |
|---|---|
| **TUIC** | QUIC-based, looks like standard HTTPS/3 — hardest to block |
| **Hysteria2** | QUIC-based, obfuscated, good on high-latency links |
| **VLESS + Reality** | TLS fingerprint of real TLS 1.3 — very hard to distinguish |
| **Trojan** | Mimics HTTPS — generally reliable |
| **VMess** | Widely used but detectable by entropy analysis |
| **Shadowsocks** | Detectable; less reliable on Irancell after late 2025 HTTP/3 throttling |

The workflow sorts within each tier by this order automatically.

---

## Related projects

- [JavidNet](https://github.com/Iman/javidnet) — Direction B: helping people *inside* Iran reach the global internet during shutdowns via hidden Starlink exit nodes and Snowflake-style SHOMA bridge relays
- [iran-proxy-checker](https://github.com/Iman/iran-proxy-checker) — companion repo; verifies which configs actually route into Iranian IP space via Armenian bridge servers

---

## Disclaimer

This project collects publicly available proxy configurations and performs network verification. It is intended for researchers, journalists, and members of the Iranian diaspora who need legitimate access to Iranian government services, cultural archives, and academic resources.

*"در تاریکی، یک چراغ کافیست" — In darkness, one light is enough.*
