import base64
import hashlib
import hmac
import os
import stat

import pytest
import responses

from pritunl_toolbox.api import PritunlAPIError, PritunlClient, ReadOnlyError, sign_request
from pritunl_toolbox.config import ConfigError, Profile, load_file, load_profile, save_profile
from pritunl_toolbox.output import csv_safe, sanitize


def test_signature_matches_reference_algorithm():
    h = sign_request("tok", "sec", "get", "/status", timestamp="1700000000", nonce="abc")
    expected = base64.b64encode(hmac.new(
        b"sec", b"tok&1700000000&abc&GET&/status", hashlib.sha256).digest()).decode()
    assert h["Auth-Signature"] == expected
    assert h["Auth-Token"] == "tok"


def profile(**kw):
    base = dict(name="t", url="https://vpn.example.test", api_token="t", api_secret="s")
    base.update(kw)
    return Profile(**base)


def test_path_segments_are_quoted():
    with responses.RequestsMock() as rsps:
        rsps.get("https://vpn.example.test/user/a%2F..%2Fb", json=[])
        assert PritunlClient(profile()).users("a/../b") == []


def test_url_prefix_is_signed(monkeypatch):
    with responses.RequestsMock() as rsps:
        rsps.get("https://vpn.example.test/pritunl/status", json={"ok": 1})
        PritunlClient(profile(url="https://vpn.example.test/pritunl")).status()
        req = rsps.calls[0].request
        ts, nonce = req.headers["Auth-Timestamp"], req.headers["Auth-Nonce"]
        msg = f"t&{ts}&{nonce}&GET&/pritunl/status".encode()
        assert req.headers["Auth-Signature"] == base64.b64encode(
            hmac.new(b"s", msg, hashlib.sha256).digest()).decode()


def test_redirects_not_followed():
    with responses.RequestsMock() as rsps:
        rsps.get("https://vpn.example.test/status", status=302,
                 headers={"Location": "https://evil.example/"})
        with pytest.raises(PritunlAPIError, match="redirect"):
            PritunlClient(profile()).status()
        assert len(rsps.calls) == 1


def test_read_only_blocks_writes():
    with pytest.raises(ReadOnlyError):
        PritunlClient(profile(read_only=True)).set_user_disabled("o", "u", True)


def test_retry_resigns_with_new_nonce(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    with responses.RequestsMock() as rsps:
        rsps.get("https://vpn.example.test/status", status=503)
        rsps.get("https://vpn.example.test/status", json={"ok": 1})
        assert PritunlClient(profile()).status() == {"ok": 1}
        nonces = {c.request.headers["Auth-Nonce"] for c in rsps.calls}
        assert len(nonces) == 2


def test_401_has_helpful_message():
    with responses.RequestsMock() as rsps:
        rsps.get("https://vpn.example.test/status", status=401)
        with pytest.raises(PritunlAPIError, match="clock"):
            PritunlClient(profile()).status()


def test_save_profile_is_private_and_roundtrips(tmp_path):
    path = tmp_path / "cfg" / "config.toml"
    save_profile("prod", {"url": "https://x", "api_token": 'a"b', "api_secret": "s\\x",
                          "read_only": True}, path=path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    data = load_file(path)
    assert data["default_profile"] == "prod"
    assert data["profiles"]["prod"]["api_token"] == 'a"b'
    assert data["profiles"]["prod"]["api_secret"] == "s\\x"


def test_load_profile_env_and_secret_cmd(tmp_path, monkeypatch):
    for k in ("PRITUNL_URL", "PRITUNL_API_TOKEN", "PRITUNL_API_SECRET", "PRITUNL_PROFILE"):
        monkeypatch.delenv(k, raising=False)
    path = tmp_path / "config.toml"
    save_profile("p", {"url": "vpn.example.test", "api_token": "t",
                       "api_secret_cmd": "echo from-cmd"}, path=path)
    prof = load_profile(path=path)
    assert prof.api_secret == "from-cmd"
    assert prof.url == "https://vpn.example.test"
    assert "from-cmd" not in str(prof.describe())
    with pytest.raises(ConfigError):
        load_profile("missing", path=path)


def test_world_readable_config_warns(tmp_path, monkeypatch):
    monkeypatch.delenv("PRITUNL_PROFILE", raising=False)
    path = tmp_path / "config.toml"
    save_profile("p", {"url": "https://x", "api_token": "t", "api_secret": "s"}, path=path)
    os.chmod(path, 0o644)
    warnings = []
    load_profile(path=path, warn=warnings.append)
    assert any("chmod 600" in w for w in warnings)


def test_sanitize_and_csv_safe():
    assert sanitize("a\x1b[2Jb\x07c‮d") == "abcd"
    assert csv_safe("=1+1") == "'=1+1"
    assert csv_safe("-cmd") == "'-cmd"
    assert csv_safe("normal") == "normal"
