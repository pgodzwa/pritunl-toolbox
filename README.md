# pritunl-toolbox

A **read-only** command-line toolbox and interactive terminal UI for
[Pritunl](https://pritunl.com) VPN admins. It never changes anything on your Pritunl server: the
API client refuses every request that is not `GET`/`HEAD`. It answers the questions the web
console makes awkward:

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
  report. Select a row for details, audit log and server logs.

```text
$ ptb online --server prod
┏━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Org         ┃ User  ┃ Groups      ┃ Server   ┃ VPN IP   ┃ Real IP      ┃ Connected ┃ Device       ┃
┡━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ Engineering │ alice │ devops, sre │ prod-vpn │ 10.8.0.2 │ 203.0.113.10 │ 1h30m     │ alice-mbp    │
│ Contractors │ carol │ contractors │ prod-vpn │ 10.8.0.4 │ 198.51.100.7 │ 10m       │ carol-laptop │
└─────────────┴───────┴─────────────┴──────────┴──────────┴──────────────┴───────────┴──────────────┘
```

## Install and update

Requires Python 3.10+. Every change merged to `main` is published as a
[GitHub release](https://github.com/pgodzwa/pritunl-toolbox/releases) (`v1.0.0`, `v1.0.1`, …) with a wheel, sdist and `SHA256SUMS`.
[pipx](https://pipx.pypa.io) is recommended: it gives the tool its own virtualenv.

### Latest version

```bash
pipx install "git+https://github.com/pgodzwa/pritunl-toolbox@main"           # main == the latest release
ptb --version
```

Update to the newest release later:

```bash
pipx upgrade pritunl-toolbox
# or, equivalently
pipx install --force "git+https://github.com/pgodzwa/pritunl-toolbox@main"
```

If `ptb --version` shows something like `0.1.dev9+g9459a08` or `1.0.1.dev2+g…`, you installed a
commit that has not been released yet. That happens if you install from `main` in the minute
before its release finishes, or when a merge was marked `[skip release]`. Re-run the upgrade
later, or pin a release tag as shown below.

### A specific version

Every release is a tag, so pin it with `@vX.Y.Z`. The same command upgrades, downgrades or
re-pins an existing install:

```bash
pipx install --force "git+https://github.com/pgodzwa/pritunl-toolbox@v1.0.0"
ptb --version                            # pritunl-toolbox, version 1.0.0
```

The prebuilt wheel works too (replace both version numbers):

```bash
pipx install --force "https://github.com/pgodzwa/pritunl-toolbox/releases/download/v1.0.0/pritunl_toolbox-1.0.0-py3-none-any.whl"
```

Find the latest version number on the [releases page](https://github.com/pgodzwa/pritunl-toolbox/releases/latest), with
`gh release view --repo pgodzwa/pritunl-toolbox`, or with
`curl -s https://api.github.com/repos/pgodzwa/pritunl-toolbox/releases/latest | grep tag_name`.

### Verified install (hash-pinned)

For servers and jump hosts, install an exact release with checksum verification for the package
*and* every dependency. Each release ships its `requirements.txt` with sha256 hashes:

```bash
V=1.0.0
base=https://github.com/pgodzwa/pritunl-toolbox/releases/download/v$V
curl -fsSLO "$base/pritunl_toolbox-$V-py3-none-any.whl"
curl -fsSLO "$base/requirements.txt"
curl -fsSLO "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS        # must print OK for both files

python3 -m venv ~/.local/share/pritunl-toolbox
~/.local/share/pritunl-toolbox/bin/pip install --require-hashes -r requirements.txt
~/.local/share/pritunl-toolbox/bin/pip install --no-deps "pritunl_toolbox-$V-py3-none-any.whl"
ln -sf ~/.local/share/pritunl-toolbox/bin/ptb ~/.local/bin/ptb
```

To update, repeat with the new version number (and `pip install --force-reinstall --no-deps`
for the wheel).

### Plain pip

```bash
pip install "git+https://github.com/pgodzwa/pritunl-toolbox@v1.0.0"                      # exact version
pip install --upgrade "git+https://github.com/pgodzwa/pritunl-toolbox@main"              # latest
```

### Uninstall

```bash
pipx uninstall pritunl-toolbox
```

Installing from GitHub needs read access to the repository. If it is private, use an
authenticated URL (e.g. via `gh auth setup-git`) or download the release assets with
`gh release download`.

Both `pritunl-toolbox` and the short alias `ptb` are installed.

## Configure

1. In Pritunl, open **Administrators**, pick (or create) an admin, enable **API access** and copy
   the API token and secret. Use a dedicated admin for the toolbox so you can revoke it separately.
   The toolbox only reads; it never uses the admin's write permissions.
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
| `server show NAME` | Server details, orgs, routes, hosts and connected users |
| `server logs NAME -n 100` | Server process output |
| `report [--inactive-days 90] [--allowed-countries PL,DE]` | Health and security findings, including impossible travel when GeoIP is available. Exit code 3 if any are high severity |
| `travel [QUERY] [--audit --days 30]` | Impossible-travel detection from live sessions and, with `--audit`, from Pritunl's audit history |
| `geo setup` | Wizard: download MaxMind GeoLite2 (free account) and configure GeoIP |
| `geo update [--force]` | Refresh GeoLite2 with stored credentials (for cron) |
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
| **5 Servers** | Server list with online users per server. Select one for connected users and server logs |
| **6 Report** | Findings by severity, with an allowed-countries input |

**Navigation.** Switching tabs always lands on the tab's table, so arrow keys and the next
`1`–`6` work straight away. To type a query, press `/`, or Enter on an empty table such as
Search before the first query. Inside a text box, digits are text, so use `Esc` to return to the
table or `F1`–`F6` to switch tabs directly.

| Key | Action |
| --- | --- |
| `1`–`6`, `[` / `]` | Go to a tab / previous or next tab |
| `F1`–`F6` | Go to a tab from anywhere, even while typing in a box |
| `↑` `↓` `PgUp` `PgDn` | Move in a table |
| `Enter` | Open details for the row: a user, a server (who is connected, logs), or a jump (country or platform → filtered Online tab; duplicate IP → Whois) |
| `/` | Jump to the tab's filter or query box |
| `Enter` in a box | Apply and go back to the table |
| `Enter` on an empty table | Jump to the tab's query box |
| `Esc` or `↓` in a box | Back to the table |
| `Esc` | Close a dialog (`l` inside one loads the audit log or server logs) |
| `r` / `a` | Refresh now / toggle auto-refresh |
| `x` | Export the current table to CSV (`~/pritunl-toolbox-exports/`, directory `700`, files `600`) |
| `g` | GeoIP setup (MaxMind GeoLite2 download form) |
| `?` / `q` | Help / quit |

The tab bar is clickable but stays out of the `Tab`-key cycle, so `Tab` only moves between the
controls of the current tab. While a dialog is open, the global keys are disabled, so nothing
changes behind it.

## GeoIP, location search and impossible travel

Geo features use local MaxMind-format databases, so **lookups never leave your machine**.

**Quickest setup: `ptb geo setup`** (or press `g` in the TUI). The wizard:

1. explains how to get a free [MaxMind account](https://www.maxmind.com/en/geolite2/signup) and
   [license key](https://www.maxmind.com/en/accounts/current/license-key);
2. asks for the account ID and license key (the key is hidden and never passed on the command
   line; `PRITUNL_MAXMIND_LICENSE_KEY` also works);
3. lets you pick databases: City (needed for impossible travel), ASN, or Country only;
4. asks for the install directory (default `~/.local/share/GeoIP`);
5. asks how to store the credentials for updates: in the config file (`600`), via a
   password-manager command, or not at all;
6. downloads over HTTPS, verifies MaxMind's SHA-256, checks each file really is the expected
   database, installs it atomically, updates the config and runs a test lookup;
7. offers to add a cron job (`ptb geo update --quiet`, twice a week after MaxMind's releases).

`ptb geo update` refreshes the data with the stored credentials. It skips databases younger than
3 days because MaxMind limits daily downloads; `--force` overrides that. The download only
talks to MaxMind and changes nothing on the Pritunl server.

Other database sources work too:

- **MaxMind `geoipupdate`** with `EditionIDs GeoLite2-City GeoLite2-ASN`.
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

- **Strictly read-only.** There are no write commands. The API client refuses any HTTP method
  other than `GET`/`HEAD` before sending it, whatever the configuration, and the test suite
  fails if any command sends a write request.
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
  `geo setup` / `geo update` send the MaxMind license key in an auth header (never in a URL),
  never forward it to the storage redirect, verify the SHA-256, cap sizes, and read only the
  `.mmdb` member from the archive, so path traversal or links inside it have no effect.
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

## Releases and versioning

`.github/workflows/release.yml` runs on every push to `main`. It runs the full CI, computes the
next version and publishes a GitHub release with the wheel, sdist, `requirements.txt` and
`SHA256SUMS`, plus auto-generated notes. The package version comes from the git tag
(`setuptools-scm`), so `ptb --version` always matches the release.

Version bumps are decided by `scripts/release_version.py` from the **titles** of the commits
merged since the last release. A title is the commit subject or, for a merge commit, the PR
title. Words elsewhere in a description do not count.

| In a PR / commit title | Bump | Example |
| --- | --- | --- |
| *(nothing special)* | patch | `1.0.0 → 1.0.1` |
| `feat:` / `feat(scope):` or `[minor]` | minor | `1.0.1 → 1.1.0` |
| `type!:` (e.g. `refactor!:`), `[major]`, or a `BREAKING CHANGE:` footer line | major | `1.1.0 → 2.0.0` |
| `[skip release]` in the title of the merged PR / pushed commit | no release | |

The first release is `v1.0.0`.

## License

pritunl-toolbox is free software, licensed under the
[GNU General Public License v3.0 or later](LICENSE) (`GPL-3.0-or-later`).

- **You may** use it for any purpose, including commercially and inside a company, and you may
  study, change and share it.
- **If you distribute** it, modified or not, you must pass the same freedoms on: provide the
  source under GPL-3.0-or-later and keep the license and copyright notices.
- **There is no warranty**; see the license for details.

All runtime dependencies use GPL-3.0-compatible licenses (MIT, BSD, Apache-2.0, MPL-2.0,
PSF-2.0). The toolbox contains no Pritunl code and only talks to Pritunl's HTTP API; your use of
your Pritunl server stays under Pritunl's own license.

GeoIP databases are not part of this project. You download them yourself, under their own terms:
MaxMind GeoLite2 under the GeoLite2 End User License Agreement, and DB-IP lite under CC BY 4.0.
Both require attribution if you publish data derived from them.

## Roadmap ideas

- Session history: persist `online --watch` events to SQLite and answer "who had 10.8.0.15 last
  Tuesday at 14:00?" This would also give impossible-travel detection history without audit logs.
- Flag connections from known VPN/proxy/Tor exit ranges and hosting ASNs using local lists
- Read-only offboarding check: compare a CSV of leavers against enabled VPN accounts
- Prometheus exporter (`ptb exporter`) for sessions per server, users online, and findings
- Optional encrypted local cache for very large installations
- Notifications (Slack/webhook) for `report` findings and watched events
