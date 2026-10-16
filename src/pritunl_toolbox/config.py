"""Profile/credential handling.

Resolution order for every setting (highest wins):
  1. environment variables (PRITUNL_URL, PRITUNL_API_TOKEN, PRITUNL_API_SECRET, ...)
  2. the selected profile in the config file
  3. built-in defaults

The API secret is deliberately *not* accepted as a command line flag: argv is visible to
other local users via ``ps`` and ends up in shell history. Use the config file (mode 0600),
an environment variable, or ``api_secret_cmd`` (e.g. ``pass show pritunl/prod``).
"""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib


class ConfigError(Exception):
    pass


ENV_PREFIX = "PRITUNL_"


def default_config_path() -> Path:
    env = os.environ.get("PRITUNL_TOOLBOX_CONFIG")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "pritunl-toolbox" / "config.toml"


@dataclass
class Profile:
    name: str
    url: str
    api_token: str
    api_secret: str
    verify_tls: bool = True
    ca_bundle: str | None = None
    timeout: float = 15.0
    workers: int = 4

    def describe(self) -> dict[str, Any]:
        """Profile as a dict that is safe to print (secret redacted)."""
        return {
            "profile": self.name,
            "url": self.url,
            "api_token": _redact(self.api_token),
            "api_secret": "********" if self.api_secret else "",
            "verify_tls": self.verify_tls,
            "ca_bundle": self.ca_bundle,
            "timeout": self.timeout,
            "mode": "read-only (always)",
            "workers": self.workers,
        }


def _redact(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return value[:4] + "…" + value[-2:]


def _check_permissions(path: Path, warn) -> None:
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        warn(
            f"config file {path} is accessible by group/others "
            f"(mode {stat.filemode(mode)}); run: chmod 600 {path}"
        )


def load_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc


def _run_secret_cmd(cmd: str, timeout: float = 30) -> str:
    # No shell: the command is split and executed directly to avoid injection surprises.
    try:
        proc = subprocess.run(  # noqa: S603
            shlex.split(cmd), capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConfigError(f"api_secret_cmd failed: {exc}") from exc
    if proc.returncode != 0:
        # stderr may contain sensitive data from password managers; don't echo it.
        raise ConfigError(f"api_secret_cmd exited with status {proc.returncode}")
    secret = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""
    if not secret:
        raise ConfigError("api_secret_cmd returned an empty secret")
    return secret


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def load_profile(
    profile_name: str | None = None,
    path: Path | None = None,
    overrides: dict[str, Any] | None = None,
    warn=None,
) -> Profile:
    warn = warn or (lambda msg: print(f"warning: {msg}", file=sys.stderr))
    path = path or default_config_path()
    data = load_file(path)
    if data:
        _check_permissions(path, warn)

    profiles = data.get("profiles", {})
    name = (
        profile_name
        or os.environ.get("PRITUNL_PROFILE")
        or data.get("default_profile")
        or ("default" if "default" in profiles else None)
    )
    raw: dict[str, Any] = {}
    if name:
        if name not in profiles and profile_name:
            raise ConfigError(f"profile '{name}' not found in {path}")
        raw = dict(profiles.get(name, {}))
    name = name or "env"

    env_map = {
        "url": "URL",
        "api_token": "API_TOKEN",
        "api_secret": "API_SECRET",
        "ca_bundle": "CA_BUNDLE",
        "timeout": "TIMEOUT",
    }
    for key, env in env_map.items():
        val = os.environ.get(ENV_PREFIX + env)
        if val:
            raw[key] = val

    for key, val in (overrides or {}).items():
        if val is not None:
            raw[key] = val

    if not raw.get("api_secret") and raw.get("api_secret_cmd"):
        raw["api_secret"] = _run_secret_cmd(str(raw["api_secret_cmd"]))

    missing = [k for k in ("url", "api_token", "api_secret") if not raw.get(k)]
    if missing:
        raise ConfigError(
            "missing " + ", ".join(missing) + f" (profile '{name}', config {path}). "
            "Run 'pritunl-toolbox config init' or set PRITUNL_URL / PRITUNL_API_TOKEN / "
            "PRITUNL_API_SECRET."
        )

    url = str(raw["url"]).rstrip("/")
    if not url.startswith(("https://", "http://")):
        url = "https://" + url
    if url.startswith("http://"):
        warn("using plain HTTP: API signatures and all user data travel unencrypted")

    try:
        timeout = float(raw.get("timeout", 15))
        workers = max(1, min(16, int(raw.get("workers", 4))))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"invalid numeric setting: {exc}") from exc

    return Profile(
        name=name,
        url=url,
        api_token=str(raw["api_token"]),
        api_secret=str(raw["api_secret"]),
        verify_tls=_as_bool(raw.get("verify_tls", True)),
        ca_bundle=raw.get("ca_bundle") or None,
        timeout=timeout,
        workers=workers,
    )


def load_geo_settings(path: Path | None = None) -> dict[str, Any]:
    """The top-level [geoip] table: city / asn database paths and autodiscover flag."""
    geo = load_file(path or default_config_path()).get("geoip", {})
    return dict(geo) if isinstance(geo, dict) else {}


# --------------------------------------------------------------------------- writing


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    # JSON string escaping produces a valid TOML basic string.
    return json.dumps(str(value), ensure_ascii=False)


def dump_toml(data: dict[str, Any]) -> str:
    lines: list[str] = []
    for key, val in data.items():
        if not isinstance(val, dict):
            lines.append(f"{key} = {_toml_value(val)}")
    for key, table in data.items():
        if not isinstance(table, dict):
            continue
        if not any(isinstance(v, dict) for v in table.values()):
            # flat table such as [geoip]
            lines.append("")
            lines.append(f"[{key}]")
            lines.extend(f"{k} = {_toml_value(v)}" for k, v in table.items() if v is not None)
            continue
        for pname, pdata in table.items():
            lines.append("")
            lines.append(f"[{key}.{json.dumps(pname)}]")
            for k, v in pdata.items():
                if v is None:
                    continue
                lines.append(f"{k} = {_toml_value(v)}")
    return "\n".join(lines) + "\n"


def _write_config(data: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Create with 0600 from the start so the secret is never world-readable, even briefly.
    tmp = path.with_suffix(".tmp")
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()  # stale temp file or planted symlink: never write through it
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(dump_toml(data))
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return path


def save_profile(name: str, values: dict[str, Any], path: Path | None = None,
                 make_default: bool = False) -> Path:
    path = path or default_config_path()
    data = load_file(path)
    data.setdefault("profiles", {})[name] = {k: v for k, v in values.items() if v is not None}
    if make_default or "default_profile" not in data:
        data["default_profile"] = name
    return _write_config(data, path)


def save_geo_settings(values: dict[str, Any], path: Path | None = None) -> Path:
    """Merge ``values`` into the [geoip] table; a value of None removes that key."""
    path = path or default_config_path()
    data = load_file(path)
    geo = dict(data.get("geoip") or {})
    for key, value in values.items():
        if value is None:
            geo.pop(key, None)
        else:
            geo[key] = value
    data["geoip"] = geo
    return _write_config(data, path)
