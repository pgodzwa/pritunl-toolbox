import pytest
from conftest import NOW, USERS

from pritunl_toolbox.models import User, parse_ip
from pritunl_toolbox.query import Query, QueryError, parse_duration


@pytest.fixture
def users():
    out = []
    for org_users in USERS.values():
        out.extend(User.from_api(u) for u in org_users)
    return out


def names(query, users, *parts):
    return sorted(m.user.name for m in Query.parse(parts, now=NOW).run(users))


@pytest.mark.parametrize("raw,expected", [
    ("1.2.3.4", "1.2.3.4"), ("1.2.3.4:1194", "1.2.3.4"), ("10.8.0.2/24", "10.8.0.2"),
    ("[fd00::1]:443", "fd00::1"), ("fd00::2/64", "fd00::2"), ("garbage", None), (None, None),
])
def test_parse_ip(raw, expected):
    ip = parse_ip(raw)
    assert (str(ip) if ip else None) == expected


def test_bare_ip_matches_vpn_or_real(users):
    assert names(None, users, "10.8.0.2") == ["alice"]
    assert names(None, users, "203.0.113.10") == ["alice", "dave"]  # real IP, port stripped
    assert names(None, users, "10.8.0.3") == ["bob", "erin"]  # assigned, offline


def test_cidr_glob_prefix(users):
    assert names(None, users, "rip:203.0.113.0/24") == ["alice", "dave"]
    assert names(None, users, "vip:10.9.*") == ["alice", "bob", "dave"]
    assert names(None, users, "vip:10.8.0.") == ["alice", "bob", "carol", "dave", "erin"]


def test_entry_terms_must_match_same_server(users):
    # dave is online on prod and staging, but his staging IP is 10.9.0.5
    assert names(None, users, "server:staging", "rip:203.0.113.10") == []
    assert names(None, users, "server:prod", "rip:203.0.113.10") == ["alice", "dave"]
    assert names(None, users, "server:staging", "status:online") == ["dave"]


def test_groups_and_negation(users):
    assert names(None, users, "group:dev") == ["bob", "dave"]  # exact, not 'devops'
    assert names(None, users, "group:dev*") == ["alice", "bob", "dave"]
    assert names(None, users, "group:sre,contractors") == ["alice", "carol"]
    assert names(None, users, "-group:dev", "status:online") == ["alice", "carol"]
    assert names(None, users, "-status:online") == ["bob", "erin"]
    assert names(None, users, "-server:staging") == ["carol", "erin"]


def test_text_and_value_forms(users):
    assert names(None, users, "ali") == ["alice"]
    assert names(None, users, "name:=bo") == []
    assert names(None, users, "name:~^(bob|carol)$") == ["bob", "carol"]
    assert names(None, users, "org:contract") == ["carol"]
    assert names(None, users, "email:alice@") == ["alice"]


def test_status_and_flags(users):
    assert names(None, users, "status:disabled") == ["carol"]
    assert names(None, users, "status:offline") == ["bob", "erin"]
    assert names(None, users, "bypass2fa:yes") == ["carol"]
    assert names(None, users, "platform:win") == ["carol", "dave"]
    assert names(None, users, "inactive:90d") == ["bob", "erin"]
    assert names(None, users, "active:1d") == ["alice", "carol", "dave"]


def test_errors():
    with pytest.raises(QueryError):
        Query.parse(["bogus:1"])
    with pytest.raises(QueryError):
        Query.parse(["vip:not-an-ip"])
    with pytest.raises(QueryError):
        Query.parse(["name:~("])
    with pytest.raises(QueryError):
        parse_duration("soon")


def test_ipv6_bare_term_not_treated_as_key():
    q = Query.parse(["fd00::1"])
    assert q.terms[0].key == "ip"


def test_matched_entries(users):
    q = Query.parse(["server:staging"])
    alice = next(u for u in users if u.name == "alice")
    assert [e.server_name for e in q.match(alice).entries] == ["staging-vpn"]
    # No server terms: live sessions are reported
    assert [e.server_name for e in Query.parse([]).match(alice).entries] == ["prod-vpn"]
