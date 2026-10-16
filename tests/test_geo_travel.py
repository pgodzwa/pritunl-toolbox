import json
import math

import pytest
from click.testing import CliRunner
from conftest import NOW

from pritunl_toolbox.cli import cli
from pritunl_toolbox.geo import GeoError, GeoResolver, resolve_paths
from pritunl_toolbox.models import GeoInfo, User
from pritunl_toolbox.travel import (
    Observation,
    audit_observations,
    detect,
    haversine_km,
    session_observations,
)


class FakeReader:
    def __init__(self, records):
        self.records = records
        self.calls = 0

    def get(self, ip):
        self.calls += 1
        return self.records.get(ip)


MAXMIND_CITY = {"8.8.8.8": {
    "country": {"iso_code": "US", "names": {"en": "United States"}},
    "city": {"names": {"en": "Mountain View"}},
    "location": {"latitude": 37.4, "longitude": -122.1, "accuracy_radius": 1000},
}}
MAXMIND_ASN = {"8.8.8.8": {"autonomous_system_number": 15169,
                           "autonomous_system_organization": "GOOGLE"}}
IPINFO = {"1.1.1.1": {"country_code": "AU", "country": "Australia", "asn": "AS13335",
                      "as_name": "Cloudflare, Inc."}}


def test_maxmind_layout_and_cache():
    city = FakeReader(MAXMIND_CITY)
    r = GeoResolver(city, FakeReader(MAXMIND_ASN))
    info = r.lookup("8.8.8.8:443")
    assert (info.country, info.city, info.asn, info.as_org) == ("US", "Mountain View", 15169,
                                                               "GOOGLE")
    assert info.accuracy_km == 1000 and info.has_location
    assert info.label == "US Mountain View" and info.asn_label == "AS15169 GOOGLE"
    r.lookup("8.8.8.8")
    assert city.calls == 1  # memoised


def test_ipinfo_combined_layout():
    reader = FakeReader(IPINFO)
    r = GeoResolver(reader, reader)
    info = r.lookup("1.1.1.1")
    assert (info.country, info.country_name, info.asn) == ("AU", "Australia", 13335)
    assert not info.has_location


def test_private_and_unknown_addresses():
    r = GeoResolver(FakeReader({}))
    assert r.lookup("10.1.2.3").private
    assert r.lookup("9.9.9.9") is None
    assert r.lookup("not-an-ip") is None


def test_resolve_paths(tmp_path, monkeypatch):
    monkeypatch.delenv("PRITUNL_GEOIP_CITY", raising=False)
    monkeypatch.delenv("PRITUNL_GEOIP_ASN", raising=False)
    monkeypatch.setenv("PRITUNL_GEOIP_AUTODISCOVER", "1")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    (tmp_path / "GeoIP").mkdir()
    (tmp_path / "GeoIP" / "dbip-city-lite-2026-01.mmdb").write_bytes(b"x")
    (tmp_path / "GeoIP" / "dbip-city-lite-2026-09.mmdb").write_bytes(b"x")
    city, _ = resolve_paths({})
    assert city.name == "dbip-city-lite-2026-09.mmdb"  # newest wins
    with pytest.raises(GeoError):
        resolve_paths({"city": str(tmp_path / "missing.mmdb")})
    monkeypatch.setenv("PRITUNL_GEOIP_AUTODISCOVER", "0")
    assert resolve_paths({}) == (None, None)


def test_open_rejects_garbage_file(tmp_path):
    bad = tmp_path / "bad.mmdb"
    bad.write_bytes(b"not a database")
    with pytest.raises(GeoError):
        GeoResolver.open(bad, None)


# ----------------------------------------------------------------------------- travel

WAW = GeoInfo(country="PL", city="Warsaw", latitude=52.23, longitude=21.01, accuracy_km=20)
NYC = GeoInfo(country="US", city="New York", latitude=40.71, longitude=-74.0, accuracy_km=20)
KRK = GeoInfo(country="PL", city="Krakow", latitude=50.06, longitude=19.94, accuracy_km=20)


def obs(ts, ip, geo, uid="u1"):
    return Observation(uid, "Org/u1", ts, ip, geo, "audit")


def test_haversine():
    assert haversine_km(52.23, 21.01, 52.52, 13.40) == pytest.approx(517, abs=5)


def test_detect_fast_travel_and_thresholds():
    hour = 3600
    fast = detect([obs(0, "1.1.1.1", WAW), obs(2 * hour, "2.2.2.2", NYC)])
    assert len(fast) == 1 and fast[0].speed_kmh > 3000 and not fast[0].concurrent
    assert detect([obs(0, "1.1.1.1", WAW), obs(10 * hour, "2.2.2.2", NYC)]) == []
    # Warsaw -> Krakow (~250 km) is below the default 500 km minimum even if instant
    assert detect([obs(0, "1.1.1.1", WAW), obs(0, "3.3.3.3", KRK)]) == []
    # imprecise locations: accuracy radius eats the distance
    vague = GeoInfo(latitude=WAW.latitude, longitude=WAW.longitude, accuracy_km=7000)
    assert detect([obs(0, "1.1.1.1", vague), obs(60, "2.2.2.2", NYC)]) == []


def test_concurrent_sessions_are_infinite_speed():
    u = User.from_api({"id": "u", "name": "n", "organization": "o", "organization_name": "O",
                       "servers": []})
    from pritunl_toolbox.models import ServerEntry
    u.servers = [
        ServerEntry("s1", "a", connected=True, real_address="1.1.1.1",
                    connected_since=int(NOW - 7200), geo=WAW),
        ServerEntry("s2", "b", connected=True, real_address="2.2.2.2",
                    connected_since=int(NOW - 3600), geo=NYC),
    ]
    events = detect(session_observations([u], now=NOW))
    assert any(e.concurrent and math.isinf(e.speed_kmh) for e in events)
    assert events[0].as_dict()["speed_kmh"] is None


def test_audit_observations_filters():
    class R:
        def lookup(self, ip):
            return {"1.1.1.1": WAW, "2.2.2.2": NYC}.get(ip)
    u = User.from_api({"id": "u", "name": "n", "organization": "o", "organization_name": "O"})
    audit = [{"timestamp": 100, "remote_addr": "1.1.1.1"},
             {"timestamp": 50, "remote_addr": "2.2.2.2"},  # before window
             {"timestamp": "bad", "remote_addr": "2.2.2.2"},
             {"timestamp": 200, "remote_addr": "9.9.9.9"},  # unknown location
             "garbage"]
    got = audit_observations(u, audit, R(), since=60)
    assert [(o.ts, o.ip) for o in got] == [(100.0, "1.1.1.1")]


# ----------------------------------------------------------------------------- CLI


def run(*args):
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


def test_geo_terms_require_database(fake_api):
    r = run("search", "country:PL")
    assert r.exit_code == 2


def test_online_with_geo(fake_api, fake_geo):
    data = json.loads(run("online", "-o", "json").output)
    by_user = {(d["user"], d["server_name"]): d["geo"] for d in data}
    assert by_user[("carol", "prod-vpn")]["country"] == "DE"
    r = run("online", "-o", "csv")
    assert "location" in r.output.splitlines()[0] and "PL Warsaw" in r.output


def test_search_by_country_and_asn(fake_api, fake_geo):
    assert json.loads(run("search", "country:DE", "-o", "json").output)[0]["name"] == "carol"
    names = sorted(u["name"] for u in json.loads(run("search", "asn:5617", "-o", "json").output))
    assert names == ["alice", "dave"]
    names = sorted(u["name"] for u in json.loads(
        run("search", "asn:~hetzner|orange", "-o", "json").output))
    assert names == ["alice", "carol", "dave"]
    names = sorted(u["name"] for u in json.loads(
        run("search", "--online", "-country:PL", "-o", "json").output))
    assert names == ["carol"]  # dave has a PL session, so "no PL entry" excludes him


def test_report_geo_findings(fake_api, fake_geo):
    r = run("report", "--allowed-countries", "PL", "-o", "json")
    rep = json.loads(r.output)
    checks = {(f["check"], f["subject"]) for f in rep["findings"]}
    assert ("unexpected-country", "Contractors/carol") in checks
    assert ("unexpected-country", "Engineering/dave") in checks
    assert ("unexpected-country", "Engineering/alice") not in checks
    assert ("impossible-travel", "Engineering/dave") in checks
    assert {c["country"] for c in rep["countries"]} == {"PL", "DE", "US"}


def test_report_rejects_bad_country_codes(fake_api, fake_geo):
    assert run("report", "--allowed-countries", "Poland").exit_code == 2


def test_travel_command(fake_api, fake_geo):
    r = run("travel", "-o", "json")
    assert r.exit_code == 3
    events = json.loads(r.output)
    assert [e["user"] for e in events] == ["Engineering/dave"]
    assert events[0]["concurrent"] is True


def test_travel_with_audit(fake_api, fake_geo):
    r = run("travel", "--audit", "name:=alice", "-o", "json")
    assert r.exit_code == 0  # alice only seen in Warsaw
    assert ("GET", "/user/org1/u_alice/audit") in fake_api.calls


def test_geo_lookup_and_status(fake_api, fake_geo):
    out = json.loads(run("geo", "lookup", "198.51.100.7", "-o", "json").output)
    assert out[0]["location"] == "DE Berlin"
    assert run("--no-geo", "geo", "lookup", "1.1.1.1").exit_code == 2


def test_bad_geo_path_warns_in_auto_mode(fake_api, monkeypatch, tmp_path):
    monkeypatch.setenv("PRITUNL_GEOIP_CITY", str(tmp_path / "missing.mmdb"))
    r = CliRunner().invoke(cli, ["online", "-o", "json"])
    assert r.exit_code == 0
    assert run("--geo", "online").exit_code == 2
