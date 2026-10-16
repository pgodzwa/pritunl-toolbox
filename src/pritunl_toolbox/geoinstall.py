"""Download and install MaxMind GeoLite2 databases.

Talks only to MaxMind (download.maxmind.com, HTTPS) and writes local files; it never contacts
the Pritunl server.

Safety measures:
  * credentials go in an HTTP Basic auth header (never in the URL, so they do not end up in
    proxy or server logs); redirects are followed manually, HTTPS only, and the credentials
    are NOT sent to the redirect target (MaxMind redirects to a pre-signed storage URL);
  * every archive is checked against MaxMind's published SHA-256 before it is opened;
  * download and extracted sizes are capped (protects against decompression bombs);
  * nothing is extracted by member name. Only the single regular file called
    ``<edition>.mmdb`` is read and written to a path we choose, so links, devices and
    ``../`` path traversal in the archive have no effect;
  * the result must open as a MaxMind DB of the expected type before it atomically replaces
    the installed file; temp files are always cleaned up.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from pritunl_toolbox import __version__

try:  # pragma: no cover
    import maxminddb
except ImportError:  # pragma: no cover
    maxminddb = None

DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/{edition}/download"
SIGNUP_URL = "https://www.maxmind.com/en/geolite2/signup"
LICENSE_KEY_URL = "https://www.maxmind.com/en/accounts/current/license-key"

EDITIONS = ("GeoLite2-City", "GeoLite2-ASN", "GeoLite2-Country")
DEFAULT_EDITIONS = ("GeoLite2-City", "GeoLite2-ASN")
ROLE = {"GeoLite2-City": "city", "GeoLite2-Country": "city", "GeoLite2-ASN": "asn"}

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_DB_BYTES = 512 * 1024 * 1024
CHUNK = 1024 * 1024
# MaxMind publishes GeoLite updates twice a week and limits daily downloads; skip databases
# that are newer than this unless forced.
DEFAULT_MAX_AGE_DAYS = 3

CRON_MARKER = "# pritunl-toolbox geo update"
CRON_SCHEDULE = "17 4 * * 3,6"  # shortly after MaxMind's Tuesday/Friday releases

Progress = Callable[[str, int, int | None], None]


class GeoInstallError(Exception):
    pass


@dataclass(frozen=True)
class Credentials:
    account_id: str
    license_key: str = field(repr=False)  # never printed in reprs / tracebacks

    def __repr__(self) -> str:
        return f"Credentials(account_id={self.account_id!r}, license_key='****')"


@dataclass
class InstallResult:
    edition: str
    path: Path
    build_epoch: int | None
    skipped: bool = False

    @property
    def role(self) -> str:
        return ROLE[self.edition]


def default_install_dir() -> Path:
    data_home = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data_home) / "GeoIP"


def validate_account_id(value: str) -> str:
    value = (value or "").strip()
    if not re.fullmatch(r"\d{1,12}", value):
        raise GeoInstallError("the MaxMind account ID is a number, e.g. 123456")
    return value


def validate_license_key(value: str) -> str:
    value = (value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{12,128}", value):
        raise GeoInstallError("that does not look like a MaxMind license key "
                              "(letters, digits and '_' only)")
    return value


def validate_account_id_click(value: str) -> str:
    """click value_proc: re-prompt on invalid input instead of aborting the wizard."""
    import click

    try:
        return validate_account_id(value)
    except GeoInstallError as exc:
        raise click.UsageError(str(exc)) from exc


def validate_license_key_click(value: str) -> str:
    import click

    try:
        return validate_license_key(value)
    except GeoInstallError as exc:
        raise click.UsageError(str(exc)) from exc


def load_credentials(settings: dict[str, Any]) -> Credentials | None:
    """Credentials from env (PRITUNL_MAXMIND_ACCOUNT_ID / _LICENSE_KEY) or [geoip] config."""
    from pritunl_toolbox.config import _run_secret_cmd

    account = os.environ.get("PRITUNL_MAXMIND_ACCOUNT_ID") or settings.get("maxmind_account_id")
    key = os.environ.get("PRITUNL_MAXMIND_LICENSE_KEY") or settings.get("maxmind_license_key")
    if not key and settings.get("maxmind_license_key_cmd"):
        key = _run_secret_cmd(str(settings["maxmind_license_key_cmd"]))
    if not account or not key:
        return None
    return Credentials(validate_account_id(str(account)), validate_license_key(str(key)))


# ----------------------------------------------------------------------------- download


def _new_session() -> requests.Session:
    sess = requests.Session()
    sess.headers["User-Agent"] = f"pritunl-toolbox/{__version__}"
    return sess


def _check(resp: requests.Response, edition: str) -> None:
    code = resp.status_code
    if code < 400:
        return
    messages = {
        401: "MaxMind rejected the account ID / license key",
        403: "MaxMind refused the download: check the license key is active and has "
             "GeoLite access",
        404: f"MaxMind has no database called {edition}",
        429: "MaxMind download limit reached for today; try again later",
    }
    raise GeoInstallError(messages.get(code, f"MaxMind download failed: HTTP {code}"))


def _get(session: requests.Session, url: str, creds: Credentials, edition: str, *,
         stream: bool, timeout: float) -> requests.Response:
    resp = session.get(url, auth=(creds.account_id, creds.license_key), stream=stream,
                       timeout=timeout, allow_redirects=False)
    hops = 0
    while resp.is_redirect:
        hops += 1
        location = resp.headers.get("Location", "")
        resp.close()
        target = urljoin(url, location)
        if urlsplit(target).scheme != "https" or hops > 3:
            raise GeoInstallError("MaxMind redirected to an unexpected location; aborting")
        # Pre-signed storage URL: no credentials are sent to it.
        resp = session.get(target, stream=stream, timeout=timeout, allow_redirects=False)
        url = target
    _check(resp, edition)
    return resp


def _parse_sha256(text: str) -> str:
    m = re.match(r"\s*([0-9a-fA-F]{64})\b", text or "")
    if not m:
        raise GeoInstallError("MaxMind returned an unexpected checksum file")
    return m.group(1).lower()


def _db_build_epoch(path: Path) -> int | None:
    if maxminddb is None or not path.is_file():
        return None
    try:
        reader = maxminddb.open_database(str(path))
    except (OSError, ValueError, maxminddb.InvalidDatabaseError):
        return None
    try:
        return int(reader.metadata().build_epoch)
    finally:
        reader.close()


def _unlink(path: str | None) -> None:
    if path:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def install_edition(edition: str, creds: Credentials, dest_dir: Path, *,
                    session: requests.Session | None = None, force: bool = False,
                    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
                    progress: Progress | None = None, timeout: float = 60.0) -> InstallResult:
    if edition not in EDITIONS:
        raise GeoInstallError(f"unsupported edition {edition}")
    if maxminddb is None:  # pragma: no cover
        raise GeoInstallError("the 'maxminddb' package is required")
    dest_dir = Path(dest_dir).expanduser()
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / f"{edition}.mmdb"

    current = _db_build_epoch(target)
    if not force and current and time.time() - current < max_age_days * 86400:
        return InstallResult(edition, target, current, skipped=True)

    session = session or _new_session()
    url = DOWNLOAD_URL.format(edition=edition)
    expected = _parse_sha256(
        _get(session, url + "?suffix=tar.gz.sha256", creds, edition, stream=False,
             timeout=timeout).text)

    archive_tmp = db_tmp = None
    try:
        resp = _get(session, url + "?suffix=tar.gz", creds, edition, stream=True,
                    timeout=timeout)
        total = int(resp.headers.get("Content-Length") or 0) or None
        if total and total > MAX_ARCHIVE_BYTES:
            resp.close()
            raise GeoInstallError(f"{edition} archive is unexpectedly large ({total} bytes)")
        fd, archive_tmp = tempfile.mkstemp(dir=dest_dir, prefix=".download-", suffix=".tar.gz")
        digest = hashlib.sha256()
        done = 0
        with os.fdopen(fd, "wb") as fh, resp:
            for chunk in resp.iter_content(CHUNK):
                done += len(chunk)
                if done > MAX_ARCHIVE_BYTES:
                    raise GeoInstallError(f"{edition} download exceeded the size limit")
                digest.update(chunk)
                fh.write(chunk)
                if progress:
                    progress(edition, done, total)
        if not hmac.compare_digest(digest.hexdigest(), expected):
            raise GeoInstallError(f"{edition}: SHA-256 mismatch, download rejected")

        wanted = f"{edition}.mmdb"
        try:
            with tarfile.open(archive_tmp, "r:gz") as tar:
                for member in tar:
                    if not member.isfile() or PurePosixPath(member.name).name != wanted:
                        continue
                    if member.size > MAX_DB_BYTES:
                        raise GeoInstallError(f"{wanted} in the archive is too large")
                    src = tar.extractfile(member)
                    if src is None:
                        continue
                    dfd, db_tmp = tempfile.mkstemp(dir=dest_dir, prefix=".install-",
                                                   suffix=".mmdb")
                    written = 0
                    with os.fdopen(dfd, "wb") as out, src:
                        while chunk := src.read(CHUNK):
                            written += len(chunk)
                            if written > MAX_DB_BYTES:
                                raise GeoInstallError(f"{wanted} exceeded the size limit")
                            out.write(chunk)
                    break
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise GeoInstallError(f"{edition}: cannot read archive: {exc}") from exc
        if db_tmp is None:
            raise GeoInstallError(f"{wanted} not found in the downloaded archive")

        try:
            reader = maxminddb.open_database(db_tmp)
        except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
            raise GeoInstallError(f"{edition}: downloaded file is not a valid database") from exc
        try:
            meta = reader.metadata()
            db_type, build_epoch = str(meta.database_type), int(meta.build_epoch)
        finally:
            reader.close()
        if db_type != edition:
            raise GeoInstallError(f"expected a {edition} database, got {db_type}")

        os.chmod(db_tmp, 0o644)  # public data, not secret
        os.replace(db_tmp, target)
        db_tmp = None
        return InstallResult(edition, target, build_epoch)
    finally:
        _unlink(archive_tmp)
        _unlink(db_tmp)


def install(editions: list[str] | tuple[str, ...], creds: Credentials, dest_dir: Path, *,
            force: bool = False, progress: Progress | None = None,
            session: requests.Session | None = None) -> list[InstallResult]:
    session = session or _new_session()
    return [install_edition(e, creds, dest_dir, session=session, force=force,
                            progress=progress) for e in editions]


def geo_settings_for(results: list[InstallResult], dest_dir: Path,
                     editions: list[str] | tuple[str, ...]) -> dict[str, Any]:
    """[geoip] config values pointing at freshly installed databases."""
    paths = {r.edition: str(r.path) for r in results}
    city = paths.get("GeoLite2-City") or paths.get("GeoLite2-Country")
    return {"city": city, "asn": paths.get("GeoLite2-ASN"),
            "dir": str(dest_dir), "maxmind_editions": list(editions)}


# ----------------------------------------------------------------------------- cron


def update_command() -> str:
    exe = shutil.which("pritunl-toolbox") or shutil.which("ptb")
    return (shlex.quote(exe) if exe else "pritunl-toolbox") + " geo update --quiet"


def cron_line() -> str:
    return f"{CRON_SCHEDULE} {update_command()} {CRON_MARKER}"


def install_cron(line: str | None = None) -> str:
    """Add (or replace) the update job in the current user's crontab. Returns the line."""
    crontab = shutil.which("crontab")
    if not crontab:
        raise GeoInstallError("'crontab' is not available; add the job to your scheduler "
                              "manually")
    line = line or cron_line()
    current = subprocess.run([crontab, "-l"], capture_output=True, text=True,  # noqa: S603
                             check=False, timeout=30)
    existing = current.stdout if current.returncode == 0 else ""
    kept = [ln for ln in existing.splitlines() if CRON_MARKER not in ln]
    new = "\n".join([*kept, line]) + "\n"
    proc = subprocess.run([crontab, "-"], input=new, capture_output=True, text=True,  # noqa: S603
                          check=False, timeout=30)
    if proc.returncode != 0:
        raise GeoInstallError(f"crontab update failed (exit {proc.returncode})")
    return line
