# Security

## Reporting a vulnerability

Please report security problems privately via GitHub's
**Security → Report a vulnerability** on this repository rather than in a public issue.

## Threat model and protections

pritunl-toolbox holds a Pritunl **administrator API credential** and handles **personal data**
(names, emails, IP addresses, locations). The design keeps both from leaking and treats data that
VPN clients control as untrusted.

| Risk | Mitigation |
| --- | --- |
| API secret leaked through `ps`, shell history or logs | Never accepted as a CLI flag. It comes from a `0600` config file (a looser mode triggers a warning), an env var, or `api_secret_cmd` (run without a shell; its stderr is not echoed). |
| Credential sent to the wrong host | TLS verification always on (`ca_bundle` for private CAs, `--insecure` prints a warning). HTTP redirects are refused. |
| Request replay / path manipulation | HMAC signature with a fresh nonce and timestamp on every attempt, including retries. Every URL path segment is percent-encoded. |
| Accidental changes | Profiles are `read_only` by default. Writes need a read-write profile and an explicit confirmation, in both the CLI and the TUI. |
| Secrets in output | Strict allowlist models: user `otp_secret` and organization `auth_token`/`auth_secret` are dropped at parse time. |
| Terminal / markup injection from client-controlled strings (device name, platform, logs) | Control characters, ANSI/OSC escapes and bidi overrides are stripped. Rich and Textual markup is never interpreted (TUI cells are pre-built `Text`). |
| CSV / spreadsheet formula injection | Cells starting with `= + - @` (or tab/CR) are prefixed with `'`. |
| Export files readable by others | TUI exports go to `~/pritunl-toolbox-exports` (`0700`). Files are created with `O_EXCL` and mode `0600`. |
| Leaking user IPs to third parties | GeoIP lookups are offline only, from local `.mmdb` files. No online geolocation APIs are used. |
| API overload | Bounded worker pool. `travel --audit` is capped by `--max-users`. |
| Supply chain | Hash-pinned lock files (`requirements*.txt`, installed with `--require-hashes`), `pip-audit` in CI plus a weekly scheduled run, Dependabot with a release cooldown. CI runs with a read-only token and `persist-credentials: false`. |

## Operational advice

- Create a dedicated Pritunl administrator for the toolbox, with API access enabled. You can
  then rotate or revoke its credential without affecting human admins.
- Keep production profiles `read_only = true`. Use a separate read-write profile only when you
  actually need to make changes.
- Exports and `-o json/csv` output contain personal data. Store, share and delete them under
  your data-protection rules.
- Refresh the GeoIP databases regularly (e.g. weekly with `geoipupdate`). `geo status` warns
  when they are older than 45 days.
