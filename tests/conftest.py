from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from urllib.parse import urlsplit

import pytest
import responses

URL = "https://vpn.example.test"
TOKEN = "tok_ABCDEFGHIJKLMNOP"
SECRET = "sec_0123456789abcdefghijklmnop"
NOW = time.time()
DAY = 86400


def entry(server_id, name, vip, *, rip=None, since=None, device=None, platform=None):
    online = rip is not None
    # Mirrors Pritunl's user_get: a connected entry has the *client session* id in both "id"
    # and "server_id" (pritunl/handlers/user.py); only "name" identifies the server.
    entry_id = f"sess-{server_id}-{vip}" if online else server_id
    return {
        "id": entry_id, "server_id": entry_id, "name": name, "status": online,
        "virt_address": vip, "virt_address6": None, "real_address": rip,
        "connected_since": since, "device_name": device, "platform": platform,
    }


ORGS = [
    {"id": "org1", "name": "Engineering", "user_count": 4,
     "auth_token": "ORG-TOKEN-LEAK", "auth_secret": "ORG-SECRET-LEAK"},
    {"id": "org2", "name": "Contractors", "user_count": 1,
     "auth_token": "ORG-TOKEN-LEAK", "auth_secret": "ORG-SECRET-LEAK"},
]

SERVERS = [
    {"id": "srv1", "name": "prod-vpn", "status": "online", "uptime": 7200, "users_online": 3,
     "devices_online": 3, "user_count": 5, "network": "10.8.0.0/24", "port": 1194,
     "protocol": "udp", "groups": [], "otp_auth": True},
    {"id": "srv2", "name": "staging-vpn", "status": "online", "uptime": 3600, "users_online": 1,
     "devices_online": 1, "user_count": 4, "network": "10.9.0.0/24", "port": 1195,
     "protocol": "udp", "groups": ["dev"], "otp_auth": False},
]


def user(uid, name, org, groups, servers, **kw):
    d = {
        "id": uid, "name": name, "email": f"{name}@example.test", "organization": org["id"],
        "organization_name": org["name"], "groups": groups, "type": "client",
        "auth_type": "local", "disabled": False, "bypass_secondary": False, "pin": False,
        "last_active": int(NOW - 3600), "otp_secret": "OTP-SECRET-LEAK", "servers": servers,
        "client_to_client": True,
    }
    d.update(kw)
    return d


USERS = {
    "org1": [
        user("u_alice", "alice", ORGS[0], ["devops", "sre"], [
            entry("srv1", "prod-vpn", "10.8.0.2/24", rip="203.0.113.10",
                  since=int(NOW - 5400), device="alice-mbp", platform="mac"),
            entry("srv2", "staging-vpn", "10.9.0.2"),
        ]),
        user("u_bob", "bob", ORGS[0], ["dev"], [
            entry("srv1", "prod-vpn", "10.8.0.3"),
            entry("srv2", "staging-vpn", "10.9.0.3"),
        ], last_active=int(NOW - 200 * DAY)),
        user("u_dave", "dave", ORGS[0], ["dev"], [
            entry("srv1", "prod-vpn", "10.8.0.5", rip="203.0.113.10:51820",
                  since=int(NOW - 60), device="[red]evil\x1b[2J", platform="linux"),
            entry("srv2", "staging-vpn", "10.9.0.5", rip="192.0.2.50",
                  since=int(NOW - 120), device="dave-pc", platform="win"),
        ]),
        user("u_erin", "erin", ORGS[0], [], [
            entry("srv1", "prod-vpn", "10.8.0.3"),
        ], last_active=None, email="=HYPERLINK(\"http://x\")"),
    ],
    "org2": [
        user("u_carol", "carol", ORGS[1], ["contractors"], [
            entry("srv1", "prod-vpn", "10.8.0.4", rip="198.51.100.7",
                  since=int(NOW - 600), device="carol-laptop", platform="win"),
        ], disabled=True, bypass_secondary=True),
    ],
}


class FakePritunl:
    """Serves canned data and validates Pritunl API signatures like the real server."""

    def __init__(self, rsps: responses.RequestsMock):
        self.rsps = rsps
        self.nonces: set[str] = set()
        self.calls: list[tuple[str, str]] = []
        self.writes: list[tuple[str, str]] = []  # any non-GET request = test failure
        rsps.add_callback(responses.GET, _rx(r"/status$"), callback=self._wrap(self.status))
        rsps.add_callback(responses.GET, _rx(r"/organization$"),
                          callback=self._wrap(lambda r: ORGS))
        rsps.add_callback(responses.GET, _rx(r"/user/[^/]+$"), callback=self._wrap(self.users))
        rsps.add_callback(responses.GET, _rx(r"/user/[^/]+/[^/]+$"),
                          callback=self._wrap(self.single_user))
        rsps.add_callback(responses.GET, _rx(r"/server$"), callback=self._wrap(lambda r: SERVERS))
        rsps.add_callback(responses.GET, _rx(r"/server/[^/]+/output$"),
                          callback=self._wrap(lambda r: {"output": ["line1", "bad\x1b[31mred"]}))
        rsps.add_callback(responses.GET, _rx(r"/server/[^/]+/organization$"),
                          callback=self._wrap(lambda r: ORGS[:1]))
        rsps.add_callback(responses.GET, _rx(r"/server/[^/]+/route$"),
                          callback=self._wrap(lambda r: [{"network": "10.0.0.0/8", "nat": True}]))
        rsps.add_callback(responses.GET, _rx(r"/server/[^/]+/host$"),
                          callback=self._wrap(lambda r: [{"name": "h1", "status": "online"}]))
        rsps.add_callback(responses.GET, _rx(r"/user/[^/]+/[^/]+/audit$"),
                          callback=self._wrap(lambda r: [{"timestamp": int(NOW), "type": "login",
                                                          "remote_addr": "203.0.113.10",
                                                          "message": "User logged in"}]))
        # The toolbox must never write: record any write attempt (checked in fixture teardown)
        import re as _re
        for method in (responses.POST, responses.PUT, responses.PATCH, responses.DELETE):
            rsps.add_callback(method, _re.compile(r".*"), callback=self._record_write)
        rsps.add_callback(responses.GET, _rx(r"/host$"), callback=self._wrap(lambda r: [
            {"id": "h1", "name": "host-1", "hostname": "vpn1", "status": "online",
             "public_addr": "198.51.100.1", "local_addr": "10.0.0.10", "uptime": 100}]))

    def _wrap(self, handler):
        def cb(request):
            path = urlsplit(request.url).path
            h = request.headers
            if h.get("Auth-Token") != TOKEN:
                return 401, {}, ""
            if abs(int(h["Auth-Timestamp"]) - time.time()) > 300:
                return 401, {}, ""
            nonce = h["Auth-Nonce"]
            if nonce in self.nonces:
                return 401, {}, ""
            self.nonces.add(nonce)
            msg = "&".join([TOKEN, h["Auth-Timestamp"], nonce, request.method, path])
            expected = base64.b64encode(
                hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).digest()).decode()
            if not hmac.compare_digest(expected, h["Auth-Signature"]):
                return 401, {}, ""
            self.calls.append((request.method, path))
            return 200, {"Content-Type": "application/json"}, json.dumps(handler(request))
        return cb

    def status(self, request):
        return {"server_version": "1.32.0", "org_count": 2, "user_count": 5, "users_online": 3,
                "server_count": 2, "servers_online": 2, "host_count": 1, "hosts_online": 1}

    def users(self, request):
        org_id = urlsplit(request.url).path.rsplit("/", 1)[-1]
        return USERS.get(org_id, [])

    def _find_user(self, request):
        _, _, org_id, user_id = urlsplit(request.url).path.split("/")[:4]
        return next(u for u in USERS[org_id] if u["id"] == user_id)

    def _record_write(self, request):
        self.writes.append((request.method, request.url))
        return 405, {}, ""

    def single_user(self, request):
        return {k: v for k, v in self._find_user(request).items() if k != "servers"}



def _rx(path_regex: str):
    import re
    return re.compile(re.escape(URL) + path_regex)


@pytest.fixture
def fake_api(monkeypatch, tmp_path):
    monkeypatch.setenv("PRITUNL_TOOLBOX_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("PRITUNL_URL", URL)
    monkeypatch.setenv("PRITUNL_API_TOKEN", TOKEN)
    monkeypatch.setenv("PRITUNL_API_SECRET", SECRET)
    monkeypatch.delenv("PRITUNL_PROFILE", raising=False)
    monkeypatch.setenv("PRITUNL_GEOIP_AUTODISCOVER", "0")
    monkeypatch.delenv("PRITUNL_GEOIP_CITY", raising=False)
    monkeypatch.delenv("PRITUNL_GEOIP_ASN", raising=False)
    import copy

    saved = copy.deepcopy(USERS)  # some tests mutate fixtures (e.g. watch); isolate them
    try:
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            api = FakePritunl(rsps)
            yield api
            assert api.writes == [], f"toolbox sent write requests: {api.writes}"
    finally:
        USERS.clear()
        USERS.update(saved)


# ----------------------------------------------------------------------------- geo

GEO_TABLE = {
    "203.0.113.10": dict(country="PL", country_name="Poland", city="Warsaw", latitude=52.23,
                         longitude=21.01, accuracy_km=20, asn=5617, as_org="Orange Polska"),
    "192.0.2.50": dict(country="US", country_name="United States", city="New York",
                       latitude=40.71, longitude=-74.0, accuracy_km=20, asn=64500,
                       as_org="Example Transit"),
    "198.51.100.7": dict(country="DE", country_name="Germany", city="Berlin", latitude=52.52,
                         longitude=13.40, accuracy_km=20, asn=24940, as_org="Hetzner Online"),
}


@pytest.fixture
def fake_geo(monkeypatch):
    """A GeoResolver that answers from GEO_TABLE (the fixture IPs are documentation ranges)."""
    from pritunl_toolbox.geo import GeoResolver
    from pritunl_toolbox.models import GeoInfo

    class TableResolver(GeoResolver):
        def _lookup(self, ip):
            data = GEO_TABLE.get(str(ip))
            return GeoInfo(**data) if data else None

        def describe(self):
            return [{"role": "city", "path": "/fake.mmdb", "type": "Fake-City",
                     "build_epoch": int(NOW), "ip_version": 6}]

    resolver = TableResolver(city_reader=object())
    monkeypatch.setattr(GeoResolver, "from_settings", classmethod(lambda cls, s=None: resolver))
    return resolver
