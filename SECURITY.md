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
| Changes to the VPN server | None are possible. The toolbox has no write commands, and the API client refuses every HTTP method other than `GET`/`HEAD` before anything is sent. Tests fail if any command sends a write request. |
| MaxMind license key leakage | Sent only as a Basic-auth header to `download.maxmind.com` over HTTPS, never in a URL and never to the storage redirect target. It is prompted hidden, stored only if you choose (config file `0600` or a password-manager command), and hidden from reprs and logs. |
| Malicious or corrupted GeoIP download | SHA-256 verified against MaxMind's checksum. Size caps protect against decompression bombs. Only the `<edition>.mmdb` regular file is read from the archive, so links, devices and `../` paths are ignored. The file must open as the expected MaxMind DB type before it atomically replaces the old one. |
| Tampered releases | Release builds use hash-pinned build tools without network build isolation. `SHA256SUMS` and a hashed `requirements.txt` are published with every release for verified installs. |
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
- The toolbox never needs Pritunl's write permissions. If your Pritunl version offers a
  read-only or audit admin role, use that for the API token.
- Exports and `-o json/csv` output contain personal data. Store, share and delete them under
  your data-protection rules.
- Refresh the GeoIP databases regularly (e.g. weekly with `geoipupdate`). `geo status` warns
  when they are older than 45 days.
