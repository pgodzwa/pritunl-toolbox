# pritunl-toolbox

A command-line toolbox for [Pritunl](https://pritunl.com) VPN admins. It answers the questions
the web console makes awkward:

- **Who is connected right now**, to which server, from where, on what device?
- **Who owns this IP?** Works for a VPN IP (assigned or live) and for a real/public IP, single
  addresses or whole CIDR ranges.
- **Search across every organization** by name, email, group, server, VPN IP, real IP, platform,
  status, inactivity and more, with negation, globs and regexes.
- **Security & hygiene report**: disabled users still connected, accounts used from several IPs at
  once, duplicate VPN IPs, users bypassing 2FA, stale accounts, servers without 2FA.

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

Requires Python 3.9+.

```bash
pipx install git+https://github.com/pgodzwa/pritunl-toolbox
# or, for development
python -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
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
| `report [--inactive-days 90]` | Health and security findings. Exit code 3 if any are high severity |

Every listing supports `-o table|json|csv`.

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
- Exports hold personal data (names, emails, IPs). Store and share them accordingly.

## Development

```bash
pip install -e '.[dev]'
pytest           # tests run against a fake Pritunl API that verifies HMAC signatures
ruff check .
```

## Roadmap ideas

- `user disconnect`, `user reset-otp`, and `user key-link` (temporary profile links) with
  audit-friendly confirmations
- Session history: persist `online --watch` events to SQLite and answer "who had 10.8.0.15 last
  Tuesday at 14:00?"
- GeoIP/ASN enrichment for real IPs, plus "impossible travel" detection
- Bulk operations from CSV: create users, set groups, disable leavers (HR offboarding sync)
- Prometheus exporter (`ptb exporter`) for sessions per server, users online, and findings
- Optional encrypted local cache for very large installations
- Notifications (Slack/webhook) for `report` findings and watched events
