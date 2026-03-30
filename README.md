# Iran Intranet Config Collector

**"اینترنت نمی‌میرد" — The Internet Never Dies**

Collects and verifies proxy/VPN configs that **exit inside Iranian IP space**, enabling researchers, journalists, and the Iranian diaspora outside Iran to reach the National Information Network (SHOMA) — government services, banking, universities, and cultural archives that are only accessible from within Iranian AS space.

> **Direction A only.** This project helps people *outside* Iran reach SHOMA resources.
> For Direction B (helping people *inside* Iran reach the global internet during shutdowns), see [JavidNet](https://github.com/Iman/javidnet).

---

## ⚠️ Why free configs have a high failure rate

**Read this first.** If you imported `ir_exit_configs.txt` and all configs failed, this explains why — and it's not a bug in this collector.

### Iran's DPI blocks most connection attempts

Iran uses a layered censorship system ([bgoldmann/iranvpn research report 2026](https://github.com/bgoldmann/iranvpn)):

| Layer | What it does |
|---|---|
| **Protocol whitelist** | Only DNS, HTTP, and HTTPS are permitted at the network layer. OpenVPN, plain WireGuard, raw UDP — all dropped before DPI even sees them. |
| **DPI engine** | Inspects packet headers and content in real time. Identifies VPN traffic by signature even on port 443. |
| **SNI filtering** | Reads the Server Name in TLS handshakes and blocks known proxy servers by hostname. |
| **Active probing** | Sends probe connections to suspected proxy servers to confirm they are proxies, then permanently blocks the IP. |

A proxy config must **look exactly like normal HTTPS browser traffic** to pass all four layers. Configs with `security=none` on port 80 are inspected by DPI and dropped. Configs that don't mimic a real browser TLS fingerprint get caught by active probing within minutes of deployment.

### The Iranian CDN fronting problem

Most configs in aggregators use **Iranian CDN infrastructure** as the server address — `185.143.x.x` (Arvan Cloud), `snapp.ir`, `arvancloud.ir`. These are set up by operators *inside* Iran to route traffic *outward* to the global internet. When you connect *from outside* Iran:

```
You (outside) ──→ 185.143.233.x (Arvan Cloud inside Iran)
                  Arvan routes your request inward into SHOMA
                  Backend proxy is configured for outbound traffic only
                  ← Connection fails / wrong response
```

The TCP port responds — that's why our check passes. But the VLESS handshake fails because the backend proxy isn't configured to accept inbound connections from the global internet for routing you *into* SHOMA. This is the wrong traffic direction.

### Free configs expire within hours

Public Telegram aggregators share configs with thousands of users simultaneously. Each UUID gets rate-limited, the operator takes the server down, or the IP gets blocked within hours. By the time a config reaches this collector, passes TCP verification, and gets committed, it may already be dead. **A 90%+ failure rate on free public configs is normal.**

---

## The reliable approach: run your own server inside Iran

The only reliable way to access SHOMA from outside is **a dedicated VPS inside Iran that you control**, running a properly configured VLESS+Reality server. Two projects make this straightforward.

### Option 1 — xtls-reality-docker (5-minute setup)

[github.com/myelectronix/xtls-reality-docker](https://github.com/myelectronix/xtls-reality-docker)

VLESS + XTLS-Reality is the highest DPI-resistance protocol available. It mimics the TLS 1.3 fingerprint of a real website (Apple, Samsung, etc.) — indistinguishable from normal HTTPS to Iranian DPI.

**Requirements:** A VPS with a public IP inside Iran (any Iranian hosting provider) and Docker installed.

```bash
# On your Iranian VPS — one command:
sudo docker run -d --rm -p 443:443 \
  -e SNI=www.samsung.com \
  -v xtls-reality-volume:/opt/xray/config \
  --name xtls-reality myelectronix/xtls-reality:latest

# Get your connection settings:
sudo docker exec xtls-reality bash get-client-settings.sh
# Output: IP Address, UUID, Public key, SNI, ShortID

# Or get a QR code to scan in v2rayNG:
sudo docker exec xtls-reality bash get-client-qr.sh
```

**Connect with NekoBox** (Windows) — add a VLESS profile:

```
Protocol:   VLESS
Address:    <your Iranian VPS IP>
Port:       443
UUID:       <from get-client-settings.sh>
Flow:       xtls-rprx-vision
Transport:  TCP
Security:   Reality
SNI:        www.samsung.com
PublicKey:  <from get-client-settings.sh>
ShortID:    <from get-client-settings.sh>
```

**Connect with v2rayNG** (Android): scan the QR code directly, or add the VLESS URI from `get-client-settings.sh`.

### Option 2 — bypasshub (full stack with active-probing defense)

[github.com/Soberia/bypasshub](https://github.com/Soberia/bypasshub)

A complete Docker-compose stack: Xray-core (VLESS+Reality) + OpenConnect VPN + NGINX front + optional Cloudflare CDN fronting. Designed specifically for the Iranian censorship environment.

The key feature: NGINX routes incoming connections by SNI — non-proxy requests get a realistic decoy webpage, defeating active probing that would otherwise identify and block your server's IP.

```bash
git clone https://github.com/Soberia/bypasshub.git
cd bypasshub
# Edit .env: set DOMAIN= and PUBLIC_IPV4=
docker compose build && docker compose up -d

# Subscription URL for clients:
# https://DOMAIN:443/subscription?username=USER&uuid=PASSWORD
```

Supports both VLESS+Reality (direct, fastest) and VLESS+WS+TLS over Cloudflare CDN (if your server IP gets blocked). See the bypasshub README for CDN setup.

### Iranian VPS providers

Any provider whose server IP resolves to an Iranian ASN will work. Confirm with `curl ip-api.com/json` — look for `"countryCode": "IR"`.

| Provider | URL |
|---|---|
| ArvanCloud Compute | arvancaas.ir |
| IranServer | iranserver.com |
| ChHost | chhost.ir |
| Hostiran | hostiran.net |
| Faranesh | faranesh.com |

---

## How this collector still helps

Even with a self-hosted server, the collected configs are useful:

**Backup connectivity** — when your primary server goes down or its IP gets blocked, the free configs give you a bridge while you provision a replacement.

**`ir_reality_configs.txt`** — surfaces any VLESS+Reality configs from the pool that exit inside Iran. These have the best chance of working because Reality is hardest for DPI to identify and block.

**Armenian bridge configs** — the South Caucasus corridor (AS42910 Ucom, AS43733 VivaCell-MTS) provides stable routes into Iranian IP space that are harder to block than direct Iranian IPs.

**Research and intelligence** — the distribution of configs across Iranian ISPs, the protocols operators are choosing, and which IP ranges remain active are all useful signals about the current state of the network.

---

## Output files explained

All files are written to `outputs/` and committed after every run.

| File | What it is | Use it for |
|---|---|---|
| `passing_intranet_configs.txt` | All verified configs — bare URIs, one per line | Full subscription import |
| **`ir_reality_configs.txt`** | **IR-exit + VLESS Reality configs** | **Best chance from free pool** |
| `ir_exit_configs.txt` | All configs with confirmed Iranian IP exit | Broad IR-exit subscription |
| `ir_mobile_exit_configs.txt` | MCI / Irancell / Rightel exits | Last to go offline during shutdowns |
| `armenian_bridge_configs.txt` | Armenian corridor bridges (AS42910, AS43733) | Stable indirect route into Iran |
| `passing_intranet_configs_base64.txt` | Base64 subscription blob | Clients that require base64 format |
| `by_protocol/` | Per-protocol splits: `vless.txt`, `hysteria2.txt`, etc. | Protocol-specific clients |

> **Subscription URL format:** Always use the **raw** URL, not the GitHub blob page.
> Change `github.com/USER/REPO/blob/main/outputs/file.txt`
> to `raw.githubusercontent.com/USER/REPO/main/outputs/file.txt`

---

## Setup (fork this repo)

1. **Fork** this repository
2. Set repository variable `IRAN_PROXY_CHECKER_REPO` → `your-username/iran-proxy-checker`
   *(Settings → Variables → Actions → New repository variable)*
3. If `iran-proxy-checker` is private, add secret `IRAN_PROXY_TOKEN` → a PAT with `repo` read scope
4. Enable Actions → the workflow runs automatically twice a day

No secrets are required if both repos are public.

---

## Verification pipeline

Each config passes through five stages before being included in output:

| Stage | What it checks | Rejects |
|---|---|---|
| **1 — Sanitise** | URI structure, encoding | `&amp%3B` HTML-encoded params; `---@channel---` chain tags; truncated URIs (`...`); HTML fragments leaked into URI |
| **2 — UUID dedup** | Server identity | Keeps one copy per UUID, preferring Reality > TLS > shortest URI |
| **3 — DNS** | Host resolves | Hostname doesn't resolve |
| **4 — TCP** | Port accepts connections within `TCP_TIMEOUT` | Port closed or firewalled |
| **5 — GeoIP** | Exit IP in Iranian or Armenian AS space | Wrong exit country |

**Optional Stage 4b — HTTP probe** (`PROBE_ENABLED=1`): sends a real WebSocket-upgrade or HTTP CONNECT request and checks whether the response looks like a live proxy rather than a CDN 404. More accurate but adds ~10 minutes to runtime. Disabled by default to stay within GitHub free-tier limits.

---

## Protocol guide

Per [bgoldmann/iranvpn](https://github.com/bgoldmann/iranvpn) and [net4people/bbs](https://github.com/net4people/bbs) current research:

| Protocol | DPI resistance | Notes |
|---|---|---|
| **VLESS + XTLS-Reality** | ⭐⭐⭐⭐⭐ | Mimics real TLS 1.3 browser fingerprint — currently the gold standard |
| **TUIC** | ⭐⭐⭐⭐ | QUIC-based; looks like HTTPS/3; good on high-latency links |
| **Hysteria2** | ⭐⭐⭐⭐ | QUIC-based obfuscated; tolerates packet loss well |
| **Trojan + TLS** | ⭐⭐⭐ | Mimics HTTPS; reliable on port 443 |
| **VLESS + WS + TLS** | ⭐⭐⭐ | WebSocket over TLS; works through CDN fronting |
| **VMess + TLS** | ⭐⭐ | Identifiable by entropy analysis over time |
| **Shadowsocks** | ⭐ | High entropy; avoid on Irancell after late 2025 HTTP/3 throttling |
| **Plain WireGuard** | ✗ | Distinctive fixed-size handshake; blocked at protocol whitelist |
| **OpenVPN** | ✗ | Recognisable encapsulation on any port |

---

## Network context

Iran's internet is controlled through a small number of state-linked operators. During the January 2026 shutdown, 2,375 BGP prefixes (26% of address space) were withdrawn.

| Operator | ASN | Role | Shutdown resilience |
|---|---|---|---|
| TCI / DCI | AS12880, AS58224 | Backbone | Lowest — lost 810 prefixes in Jan 2026 |
| MCI / Hamrahe Aval | AS197207 | Mobile (~66% market) | High — 689 routes survived Jan 2026 |
| Irancell | AS44244 | Mobile (~10% market) | High — 368 routes survived Jan 2026 |
| Rightel | AS57218 | Mobile | Medium |
| Shatel / TIC | AS48159 | Fixed ISP | Medium |
| Arvan Cloud | AS205347, AS207719 | Iranian CDN | Used for domain fronting; tends to stay up |

---

## Community and further research

- **[net4people/bbs](https://github.com/net4people/bbs)** — the primary research forum for censorship circumvention; Iran-specific threads track working techniques in real time; 4.8k stars, active
- **[bgoldmann/iranvpn](https://github.com/bgoldmann/iranvpn)** — comprehensive 2026 report on Iran's filtering system, circumvention techniques, and open-source tool evaluation
- **[OONI Explorer — Iran](https://explorer.ooni.org/country/IR)** — 40M+ measurements of Iranian internet censorship; live blocking data
- **[JavidNet](https://github.com/Iman/javidnet)** — Direction B architecture: Starlink exit nodes + Snowflake-style SHOMA relay bridges for users *inside* Iran during shutdowns

---

## Related server-side tools

| Tool | What it does |
|---|---|
| [xtls-reality-docker](https://github.com/myelectronix/xtls-reality-docker) | One-command VLESS+Reality server — Docker container, auto-generates keys |
| [bypasshub](https://github.com/Soberia/bypasshub) | Full stack: Xray + OpenConnect + NGINX active-probing defense + Cloudflare CDN |
| [Xray-core](https://github.com/XTLS/Xray-core) | The underlying proxy engine; configure directly for custom setups |

---

## Disclaimer

This project collects publicly available proxy configurations and performs automated network verification. It is intended for researchers, journalists, and members of the Iranian diaspora who need legitimate access to Iranian government services, cultural archives, and academic resources that are inaccessible from outside Iran.

*"در تاریکی، یک چراغ کافیست" — In darkness, one light is enough.*
