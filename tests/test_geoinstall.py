import hashlib
import io
import os
import stat
import tarfile
import time

import mmdb_util
import pytest
import responses
from click.testing import CliRunner

from pritunl_toolbox import geoinstall as gi
from pritunl_toolbox.cli import cli

CREDS = gi.Credentials("123456", "abcdefghijklmnop_mmk")
BASE = "https://download.maxmind.com/geoip/databases"
STORAGE = "https://storage.example.test/presigned/archive.tar.gz"


def db_bytes(edition="GeoLite2-City", epoch=None):
    record = ({"autonomous_system_number": 13335, "autonomous_system_organization": "CF"}
              if edition == "GeoLite2-ASN" else
              {"country": {"iso_code": "PL", "names": {"en": "Poland"}},
               "location": {"latitude": 52.2, "longitude": 21.0, "accuracy_radius": 20}})
    return mmdb_util.build_mmdb(record, database_type=edition,
                                build_epoch=epoch or int(time.time()) - 86400)


def make_tar(members):
    """members: list of (name, bytes | None, kind) where kind is 'file' or 'symlink'."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = data
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def good_archive(edition="GeoLite2-City", **kw):
    return make_tar([(f"{edition}_20261014/COPYRIGHT.txt", b"(c) MaxMind", "file"),
                     (f"{edition}_20261014/{edition}.mmdb", db_bytes(edition, **kw), "file")])


def mock_maxmind(rsps, edition, archive, *, sha=None, redirect=True, auth_seen=None):
    sha = sha or hashlib.sha256(archive).hexdigest()

    def checksum(request):
        if auth_seen is not None:
            auth_seen.append(("sha", request.headers.get("Authorization")))
        return 200, {}, f"{sha}  {edition}_20261014.tar.gz\n"

    def download(request):
        if auth_seen is not None:
            auth_seen.append(("download", request.headers.get("Authorization")))
        if redirect:
            return 302, {"Location": STORAGE}, ""
        return 200, {"Content-Length": str(len(archive))}, archive

    def storage(request):
        if auth_seen is not None:
            auth_seen.append(("storage", request.headers.get("Authorization")))
        return 200, {"Content-Length": str(len(archive))}, archive

    url = f"{BASE}/{edition}/download"
    rsps.add_callback(responses.GET, url + "?suffix=tar.gz.sha256", callback=checksum,
                      match=[responses.matchers.query_param_matcher(
                          {"suffix": "tar.gz.sha256"})])
    rsps.add_callback(responses.GET, url + "?suffix=tar.gz", callback=download,
                      match=[responses.matchers.query_param_matcher({"suffix": "tar.gz"})])
    if redirect:
        rsps.add_callback(responses.GET, STORAGE, callback=storage)


def leftovers(path):
    return [p.name for p in path.iterdir() if p.name.startswith(".")]


def test_install_success_and_credentials_not_forwarded(tmp_path):
    seen = []
    with responses.RequestsMock() as rsps:
        mock_maxmind(rsps, "GeoLite2-City", good_archive(), auth_seen=seen)
        result = gi.install_edition("GeoLite2-City", CREDS, tmp_path)
    assert result.path == tmp_path / "GeoLite2-City.mmdb" and not result.skipped
    assert stat.S_IMODE(os.stat(result.path).st_mode) == 0o644
    assert leftovers(tmp_path) == []
    auth = dict(seen)
    assert auth["sha"].startswith("Basic ") and auth["download"].startswith("Basic ")
    assert auth["storage"] is None  # pre-signed URL never gets the license key
    # the key never appears in any URL
    assert "abcdefghijklmnop" not in str(seen)


def test_sha_mismatch_rejected_and_cleaned(tmp_path):
    with responses.RequestsMock() as rsps:
        mock_maxmind(rsps, "GeoLite2-City", good_archive(), sha="0" * 64)
        with pytest.raises(gi.GeoInstallError, match="SHA-256"):
            gi.install_edition("GeoLite2-City", CREDS, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_wrong_database_type_rejected(tmp_path):
    archive = make_tar([("x/GeoLite2-City.mmdb", db_bytes("GeoLite2-ASN"), "file")])
    with responses.RequestsMock() as rsps:
        mock_maxmind(rsps, "GeoLite2-City", archive)
        with pytest.raises(gi.GeoInstallError, match="expected a GeoLite2-City"):
            gi.install_edition("GeoLite2-City", CREDS, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_symlink_member_is_ignored(tmp_path):
    archive = make_tar([("x/GeoLite2-City.mmdb", "/etc/passwd", "symlink")])
    with responses.RequestsMock() as rsps:
        mock_maxmind(rsps, "GeoLite2-City", archive)
        with pytest.raises(gi.GeoInstallError, match="not found"):
            gi.install_edition("GeoLite2-City", CREDS, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_path_traversal_member_cannot_escape(tmp_path):
    dest = tmp_path / "GeoIP"
    archive = make_tar([("../../evil/GeoLite2-City.mmdb", db_bytes(), "file")])
    with responses.RequestsMock() as rsps:
        mock_maxmind(rsps, "GeoLite2-City", archive)
        result = gi.install_edition("GeoLite2-City", CREDS, dest)
    assert result.path == dest / "GeoLite2-City.mmdb"
    assert not (tmp_path / "evil").exists()


def test_not_a_database_rejected(tmp_path):
    archive = make_tar([("x/GeoLite2-City.mmdb", b"#!/bin/sh\necho pwned\n", "file")])
    with responses.RequestsMock() as rsps:
        mock_maxmind(rsps, "GeoLite2-City", archive)
        with pytest.raises(gi.GeoInstallError, match="not a valid database"):
            gi.install_edition("GeoLite2-City", CREDS, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(gi, "MAX_ARCHIVE_BYTES", 100)
    with responses.RequestsMock() as rsps:
        mock_maxmind(rsps, "GeoLite2-City", good_archive(), redirect=False)
        with pytest.raises(gi.GeoInstallError, match="large|limit"):
            gi.install_edition("GeoLite2-City", CREDS, tmp_path)
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize("status,match", [(401, "account ID / license key"),
                                          (429, "limit"), (403, "GeoLite access")])
def test_http_errors_have_clear_messages(tmp_path, status, match):
    with responses.RequestsMock() as rsps:
        rsps.get(f"{BASE}/GeoLite2-City/download", status=status)
        with pytest.raises(gi.GeoInstallError, match=match):
            gi.install_edition("GeoLite2-City", CREDS, tmp_path)


def test_redirect_to_http_refused(tmp_path):
    with responses.RequestsMock() as rsps:
        rsps.get(f"{BASE}/GeoLite2-City/download", status=302,
                 headers={"Location": "http://insecure.example/x"})
        with pytest.raises(gi.GeoInstallError, match="unexpected location"):
            gi.install_edition("GeoLite2-City", CREDS, tmp_path)


def test_fresh_database_is_skipped_without_network(tmp_path):
    (tmp_path / "GeoLite2-City.mmdb").write_bytes(db_bytes(epoch=int(time.time()) - 3600))
    with responses.RequestsMock() as rsps:
        result = gi.install_edition("GeoLite2-City", CREDS, tmp_path)
        assert len(rsps.calls) == 0
    assert result.skipped


def test_credentials_validation_and_repr():
    assert "abcdef" not in repr(CREDS)
    with pytest.raises(gi.GeoInstallError):
        gi.validate_account_id("12ab")
    with pytest.raises(gi.GeoInstallError):
        gi.validate_license_key("short")
    with pytest.raises(gi.GeoInstallError):
        gi.validate_license_key("has spaces in it here")


def test_install_cron_is_idempotent(tmp_path, monkeypatch):
    store = tmp_path / "crontab.txt"
    store.write_text("0 1 * * * backup\n")
    fake = tmp_path / "bin" / "crontab"
    fake.parent.mkdir()
    fake.write_text(f'#!/bin/sh\nif [ "$1" = "-l" ]; then cat "{store}"; '
                    f'else cat > "{store}"; fi\n')
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    gi.install_cron("1 2 * * 3 ptb geo update --quiet " + gi.CRON_MARKER)
    gi.install_cron("5 6 * * 3 ptb geo update --quiet " + gi.CRON_MARKER)
    lines = store.read_text().splitlines()
    assert lines[0] == "0 1 * * * backup"
    assert [ln for ln in lines if gi.CRON_MARKER in ln] == [
        "5 6 * * 3 ptb geo update --quiet " + gi.CRON_MARKER]


# ----------------------------------------------------------------------------- CLI


def test_geo_setup_wizard_and_update(fake_api, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.delenv("PRITUNL_MAXMIND_LICENSE_KEY", raising=False)
    monkeypatch.delenv("PRITUNL_MAXMIND_ACCOUNT_ID", raising=False)
    mock_maxmind(fake_api.rsps, "GeoLite2-City", good_archive())
    mock_maxmind(fake_api.rsps, "GeoLite2-ASN", good_archive("GeoLite2-ASN"))
    answers = "\n".join([
        "12x",                    # invalid account id -> re-prompted
        "123456",
        "abcdefghijklmnop_mmk",   # license key (hidden prompt)
        "y",                      # City
        "y",                      # ASN
        "",                       # default directory
        "config",                 # store credentials
        "n",                      # no crontab
    ]) + "\n"
    r = CliRunner().invoke(cli, ["geo", "setup"], input=answers, catch_exceptions=False)
    assert r.exit_code == 0, r.output
    assert "the MaxMind account ID is a number" in r.output
    dest = tmp_path / "data" / "GeoIP"
    assert (dest / "GeoLite2-City.mmdb").is_file() and (dest / "GeoLite2-ASN.mmdb").is_file()
    assert "Test lookup 8.8.8.8 -> PL" in r.output
    assert "abcdefghijklmnop_mmk" not in r.output

    from pritunl_toolbox.config import default_config_path, load_geo_settings
    cfg = load_geo_settings()
    assert cfg["maxmind_account_id"] == "123456"
    assert cfg["maxmind_editions"] == ["GeoLite2-City", "GeoLite2-ASN"]
    assert stat.S_IMODE(os.stat(default_config_path()).st_mode) == 0o600

    # geo update: data is fresh -> skipped, no download
    calls_before = len(fake_api.rsps.calls)
    r = CliRunner().invoke(cli, ["geo", "update"], catch_exceptions=False)
    assert r.exit_code == 0 and "up to date" in r.output
    assert len(fake_api.rsps.calls) == calls_before

    # and GeoIP is now picked up automatically
    r = CliRunner().invoke(cli, ["geo", "lookup", "1.1.1.1", "-o", "json"])
    assert '"PL"' in r.output or "PL" in r.output


def test_geo_update_without_credentials(fake_api, monkeypatch):
    monkeypatch.delenv("PRITUNL_MAXMIND_LICENSE_KEY", raising=False)
    monkeypatch.delenv("PRITUNL_MAXMIND_ACCOUNT_ID", raising=False)
    r = CliRunner().invoke(cli, ["geo", "update"])
    assert r.exit_code == 1 and "geo setup" in r.output
