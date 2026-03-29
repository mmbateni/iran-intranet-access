# Iran Intranet Access Configs

Daily-updated collection of free V2Ray / VLESS / Trojan / Shadowsocks / Hysteria2
configs that can be used to access the **Iranian National Information Network (SHOMA)**
— government services, news agencies, universities, and cultural archives only
accessible from within Iranian IP space.

> **Who is this for?**  
> Iranian diaspora, researchers, journalists, and academics who need to access
> Iranian-internal resources (government portals, university repositories, news
> archives, banking services) from outside Iran.

---

## How to use

### Quickest method — import subscription

Copy this URL and paste it into **Hiddify**, **v2rayNG**, or **NekoBox**
as a subscription link:

```
https://raw.githubusercontent.com/YOUR_USERNAME/iran-intranet-access/main/outputs/passing_intranet_configs_base64.txt
```

Or download `outputs/passing_intranet_configs.txt` and import it directly.

### Manual — pick one config

Open `outputs/passing_intranet_configs.txt` and copy any URI from the top
of the file (highest-priority configs are listed first):

| Prefix in comment | What it means |
|---|---|
| `IR-exit` | Proxy exits inside Iran — full intranet access |
| `bridge-verified` | Armenian bridge proven to route into Iranian network |
| `armenian-bridge` | Armenian exit node with Iranian carrier BGP peering |
| `other-XX` | Open proxy in country XX, may have partial access |

---

## Output files

| File | Contents |
|---|---|
| `outputs/passing_intranet_configs.txt` | All verified configs, one URI per line |
| `outputs/passing_intranet_configs_base64.txt` | Base64 subscription URL |
| `outputs/passing_intranet_configs.json` | Structured JSON with metadata |
| `outputs/hiddify_intranet.json` | Top 20 configs in Hiddify outbound format |
| `outputs/by_protocol/vmess.txt` | VMess configs only |
| `outputs/by_protocol/vless.txt` | VLESS configs only |
| `outputs/by_protocol/trojan.txt` | Trojan configs only |
| `outputs/by_protocol/ss.txt` | Shadowsocks configs only |

Updated daily at **03:30 UTC** (30 minutes after iran-proxy-checker finishes).

---

## How it works

```
Public aggregators (40+ sources)
         +
iran-proxy-checker Armenian bridge configs  ←── already verified to reach IR network
         ↓
   collect_configs.py
         ↓
   TCP reachability check (can we connect to the proxy server?)
         ↓
   GeoIP classification (IR-exit / AM-bridge / other)
         ↓
   Priority ranking + deduplication
         ↓
   outputs/passing_intranet_configs.txt
```

### Priority tiers

1. **IR-exit** — proxy server's exit IP is inside Iran (confirmed by GeoIP)
2. **Bridge-verified** — ingested from [iran-proxy-checker](https://github.com/YOUR_USERNAME/iran-proxy-checker)
   Armenian bridge configs that passed a live Iranian network routing test
3. **Armenian-bridge** — exit in Armenian IP space; ArmenTel/Ucom/VivaCell-MTS
   maintain BGP peering with TCI (AS12880), MCI (AS197207), and Irancell (AS44244)
4. **Other** — open proxy in another country, unverified routing into Iran

---

## Related repos

- **[iran-proxy-checker](https://github.com/YOUR_USERNAME/iran-proxy-checker)** —
  finds proxies that let users *inside* Iran reach the global internet.
  The Armenian bridge configs discovered there feed directly into this repo.

---

## Setup (fork this repo)

1. Fork this repository
2. Set repository variable `IRAN_PROXY_CHECKER_REPO` → `your-username/iran-proxy-checker`
   (Settings → Variables → New repository variable)
3. If iran-proxy-checker is private, add secret `IRAN_PROXY_TOKEN` → PAT with repo read scope
4. Enable Actions → the workflow runs automatically every day

No secrets are required if both repos are public.

## In Outputs

ir_exit_configs.txt — IR-exit configs are the most valuable and most requested subset; they now get their own file.
armenian_bridge_configs.txt — Same rationale for the second-priority tier.
