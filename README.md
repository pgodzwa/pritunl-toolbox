# pritunl-toolbox

A command-line toolbox and interactive terminal UI for [Pritunl](https://pritunl.com) VPN admins.
It answers the questions the web console makes awkward:

- **Who is connected right now**, to which server, from where, on what device?
- **Who owns this IP?** Works for a VPN IP (assigned or live) and for a real/public IP, single
  addresses or whole CIDR ranges.
- **Search across every organization** by name, email, group, server, VPN IP, real IP, platform,
  status, inactivity and more, with negation, globs and regexes.
- **Where are they connecting from?** Offline GeoIP/ASN enrichment (country, city, provider),
  `country:`/`asn:` search, **impossible-travel** detection and allowed-country checks. No IP
  is ever sent to a third party.
- **Security & hygiene report**: disabled users still connected, accounts used from several IPs at
  once, duplicate VPN IPs, users bypassing 2FA, stale accounts, servers without 2FA.
- **Terminal UI** (`ptb tui`): dashboard, live sessions with filter, search, whois, servers,
  report. Select a row for details, audit log, server logs and enable/disable.

```text
$ ptb online --server prod
┏━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Org         ┃ User  ┃ Groups      ┃ Server   ┃ VPN IP   ┃ Real IP      ┃ Connected ┃ Device       ┃
┡━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ Engineering │ alice │ devops, sre │ prod-vpn │ 10.8.0.2 │ 203.0.113.10 │ 1h30m     │ alice-mbp    │
│ Contractors │ carol │ contractors │ prod-vpn │ 10.8.0.4 │ 198.51.100.7 │ 10m       │ carol-laptop │
└─────────────┴───────┴─────────────┴──────────┴──────────┴──────────────┴───────────┴──────────────┘
```

## Install

Requires Python 3.10+.

```bash
pipx install git+https://github.com/pgodzwa/pritunl-toolbox
```

For a reproducible, tamper-evident install, use the hash-pinned lock file. pip refuses any
package whose hash doesn't match:

```bash
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.txt
pip install --no-deps .
```

This installs two equivalent commands: `pritunl-toolbox` and the short alias `ptb`.

## Configure

1. In Pritunl, open **Administrators**, pick (or create) an admin, enable **API access** and copy
   the API token and secret. Use a dedicated admin for the toolbox so you can revoke it separately.
2. Create a profile:

```bash
ptb config init                   # prompts for URL, token and (hidden) secret
ptb config test                   # checks connectivity and credentials
```

Profiles live in `~/.config/pritunl-toolbox/config.toml` (file mode `600`). See
[`config.example.toml`](config.example.toml). Several profiles are supported
(`ptb -p staging online`), and settings can come from environment variables instead:

| Variable | Meaning |
| --- | --- |
| `PRITUNL_URL` | Base URL, e.g. `https://vpn.example.com` |
| `PRITUNL_API_TOKEN` / `PRITUNL_API_SECRET` | API credentials |
| `PRITUNL_PROFILE` | Profile name to use |
| `PRITUNL_CA_BUNDLE` | CA bundle for a private CA |
| `PRITUNL_READ_ONLY` | `true` blocks all write operations |
| `PRITUNL_TOOLBOX_CONFIG` | Alternative config file path |

Instead of storing the secret in the file you can set `api_secret_cmd`, e.g.
`api_secret_cmd = "pass show pritunl/prod"` or `"op read op://ops/pritunl/secret"`.

## Commands

| Command | What it does |
| --- | --- |
| `status` | Global counters: users/servers/hosts online, version |
| `orgs`, `servers`, `hosts` | Inventory listings (`servers --status offline`) |
| `online [QUERY]` | One row per live session. `--summary` for counts per server. `--watch 10` streams connect/disconnect events (`-o json` produces JSON lines for a SIEM) |
| `search [QUERY]` | User search across all orgs; `-x` for one row per server entry |
| `whois IP\|CIDR ...` | Who owns or uses an address: VPN IP (live or assigned) or real IP |
| `ips [QUERY]` | User→VPN IP assignment map; `--hosts --domain vpn.corp` prints hosts-file lines |
| `user show ID\|NAME\|EMAIL [--audit]` | Full user view: groups, 2FA bypass, assigned IPs per server, live sessions, audit log |
| `user disable/enable USER` | Writes (confirmation required, blocked on `read_only` profiles) |
| `server show NAME` | Server details, orgs, routes, hosts and connected users |
| `server logs NAME -n 100` | Server process output |
| `report [--inactive-days 90] [--allowed-countries PL,DE]` | Health and security findings, including impossible travel when GeoIP is available. Exit code 3 if any are high severity |
| `travel [QUERY] [--audit --days 30]` | Impossible-travel detection from live sessions and, with `--audit`, from Pritunl's audit history |
| `geo status` / `geo lookup IP...` | Which GeoIP databases are in use, and their age / local lookups |
| `tui [--refresh 30]` | Interactive terminal UI |

Every listing supports `-o table|json|csv`.

## Terminal UI

```bash
ptb tui
```

| Tab | What you get |
| --- | --- |
| **1 Dashboard** | Cards for users online, sessions, servers online, disabled-but-connected and findings; sessions per server; sessions per country (or platform) |
| **2 Online** | Live sessions. Filter while you type using the query language (`group:dev country:PL`) and narrow by server with the dropdown |
| **3 Search** | Any query (`john`, `10.8.0.15`, `inactive:90d`). The *per server* switch gives one row per server entry |
| **4 Whois** | Paste IPs or CIDRs to see who owns or uses them |
| **5 Servers** | Server list. Select one for connected users and server logs |
| **6 Report** | Findings by severity, with an allowed-countries input |

Press **Enter** on any user row for a detail view with servers, live sessions, location and a
*Load audit log* button. On read-write profiles it also has an *Enable/Disable user* button that
asks for confirmation.

Keys: `1`–`6` tabs · `/` focus filter · `r` refresh · `a` toggle auto-refresh · `x` export the
current table to CSV · `Esc` close dialog · `q` quit · `Ctrl+P` command palette.
Exports go to `~/pritunl-toolbox-exports/` (directory `700`, files `600`).

## GeoIP, location search and impossible travel

Geo features use local MaxMind-format databases, so **lookups never leave your machine**:

- **MaxMind GeoLite2** (free account): install `geoipupdate` with
  `EditionIDs GeoLite2-City GeoLite2-ASN` and run it weekly.
- **DB-IP lite** (no account, CC BY 4.0): put `dbip-city-lite-*.mmdb` and `dbip-asn-lite-*.mmdb`
  into `~/.local/share/GeoIP/`.
- **IPinfo lite** (`ipinfo_lite.mmdb`, country plus ASN, no city coordinates).

Databases in `~/.local/share/GeoIP`, `/usr/share/GeoIP` and `/var/lib/GeoIP` are found
automatically. You can also set paths in `[geoip]` (see `config.example.toml`) or with
`PRITUNL_GEOIP_CITY` / `PRITUNL_GEOIP_ASN`. Use `--no-geo` to switch enrichment off and `--geo`
to make it mandatory. `ptb geo status` shows what is in use and warns when the data is stale.

With a database present, `online`, `search -x`, `whois`, `user show` and the TUI gain
**Location** and **ASN** columns. Three query keys become available:

```text
ptb online country:DE,NL                 # sessions from Germany or the Netherlands
ptb search --online -country:PL          # online users with no session from Poland
ptb online 'asn:~hetzner|ovh|digitalocean'  # connections from hosting providers
ptb report --allowed-countries PL,DE     # flag sessions from anywhere else
```

**Impossible travel.** Each user's observed locations are put in time order. When two
consecutive locations would need a speed above `--max-speed` (default 900 km/h), a finding is
raised. Each location's accuracy radius is subtracted from the distance first, and moves shorter
than `--min-distance` (default 500 km) are ignored, which keeps false positives from imprecise
lookups and mobile carriers down.

- Live sessions alone catch one account connected from far-apart places **at the same time**.
- `ptb travel --audit --days 30` adds the remote addresses from Pritunl's per-user audit log.
  This needs auditing enabled in Pritunl and costs one API call per recently active user
  (capped by `--max-users`).

`travel` exits with code 3 when it finds something, so it can drive cron alerts.

## Query language

Used by `search`, `online` and `ips`. Terms are combined with AND:

```text
ptb search 10.8.0.15                         # bare IP: VPN IP or real IP
ptb search 203.0.113.0/24 --online           # bare CIDR
ptb search group:devops,sre -status:disabled
ptb search 'name:~^svc-' type:client
ptb search server:prod-* platform:win,mac
ptb search inactive:90d status:enabled       # stale accounts
ptb online rip:198.51.100.0/24 -group:contractors
```

| Key | Matches | Scope |
| --- | --- | --- |
| *bare word* | name, email, id, organization, groups | user |
| *bare IP/CIDR* | VPN IP or real IP | server entry |
| `name:` `email:` `id:` `org:` `group:` `type:` `auth:` | user fields (`group`, `type` and `auth` are exact by default) | user |
| `vip:` / `rip:` / `ip:` | VPN IP / real IP / either: IP, CIDR, glob `10.8.*` or prefix `10.8.` | server entry |
| `server:` `platform:` `device:` | server name, client OS, device name | server entry |
| `status:` | `online`, `offline`, `disabled`, `enabled` | mixed |
| `connected:yes\|no` | entry is live | server entry |
| `inactive:90d` / `active:24h` | last activity older / newer than (s, m, h, d, w) | user |
| `bypass2fa:yes` `pin:yes` `disabled:yes` | flags | user |
| `country:` `city:` `asn:` | ISO code or country name / city / AS number or `~provider` (GeoIP) | server entry |

Value forms: `foo` substring, `=foo` exact, `fo*` glob, `~regex`, `a,b` any of. Prefix a term with
`-` to negate it. Aliases are accepted too: `vpn_ip`, `real_ip`, `src`, `os`, `user` and others.

**Server-entry terms bind together.** `server:prod vip:10.8.0.5` means "has 10.8.0.5 *on prod*",
not "has prod access and has 10.8.0.5 on some server". A negated entry term means no entry matches.

`search` and `whois` exit with status 1 when nothing matches, so they work in scripts the way
`grep` does.

## Security notes

- **Read-only by default.** `config init` creates `read_only = true` profiles. Write commands need
  a read-write profile and ask for confirmation unless you pass `--yes`.
- **Secrets stay off argv.** The API secret is never accepted as a CLI flag, because argv is
  visible in `ps` and shell history. It comes from the config file (`600`, warned if looser),
  an environment variable, or `api_secret_cmd`, which runs without a shell.
- **TLS verification is always on.** Use `ca_bundle` for private CAs. `--insecure` exists but
  prints a warning. Redirects are never followed, so auth headers cannot go to another host.
- **Signatures are fresh on every attempt.** Each request, including retries, gets a new nonce
  and timestamp. URL path segments are percent-encoded, so IDs cannot change the request path.
- **Sensitive fields are dropped.** Only allowlisted fields are kept from API responses. User
  `otp_secret` and organization `auth_token`/`auth_secret` are discarded at parse time, so no
  output format can show them.
- **Client-supplied text is untrusted.** Values like device names and platform strings come
  from VPN clients. Control characters and ANSI escapes are stripped, rich markup is not
  interpreted, and CSV cells that start with `= + - @` are prefixed with `'` to stop
  spreadsheet formula injection.
- **No markup injection in the TUI.** Every TUI cell and label is a pre-sanitised `Text`
  object, because Textual's DataTable would otherwise parse strings as markup.
- **GeoIP stays local.** Lookups use local databases only; no IPs go to online services.
- **Pinned supply chain.** Lock files carry a sha256 hash for every transitive dependency.
  CI installs with `--require-hashes`, runs `pip-audit` on every push and weekly, and runs with
  a read-only token. Dependabot proposes updates after a 5-day cooldown.
- Exports hold personal data (names, emails, IPs, locations). Store and share them accordingly.

See [SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability.

## Development

```bash
pip install --require-hashes -r requirements-dev.txt && pip install --no-deps -e .
pytest           # fake Pritunl API that verifies HMAC signatures + headless TUI tests
ruff check .
pip-audit -r requirements.txt -r requirements-dev.txt --require-hashes --disable-pip
```

To update dependencies, bump the floors in `pyproject.toml` and regenerate the lock files with
the command at the top of each `requirements*.txt` (Dependabot does this weekly).

## Roadmap ideas

- `user disconnect`, `user reset-otp`, and `user key-link` (temporary profile links) with
  audit-friendly confirmations
- Session history: persist `online --watch` events to SQLite and answer "who had 10.8.0.15 last
  Tuesday at 14:00?" This would also give impossible-travel detection history without audit logs.
- Flag connections from known VPN/proxy/Tor exit ranges and hosting ASNs using local lists
- Bulk operations from CSV: create users, set groups, disable leavers (HR offboarding sync)
- Prometheus exporter (`ptb exporter`) for sessions per server, users online, and findings
- Optional encrypted local cache for very large installations
- Notifications (Slack/webhook) for `report` findings and watched events
