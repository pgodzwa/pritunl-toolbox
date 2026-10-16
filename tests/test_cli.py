import csv
import io
import json

import pytest
from click.testing import CliRunner
from conftest import SECRET

from pritunl_toolbox.cli import cli


def run(*args, input=None):
    result = CliRunner().invoke(cli, list(args), input=input, catch_exceptions=False)
    return result


def test_status(fake_api):
    r = run("status", "-o", "json")
    assert r.exit_code == 0
    assert json.loads(r.output)["server_version"] == "1.32.0"


def test_online_lists_sessions(fake_api):
    r = run("online", "-o", "json")
    data = json.loads(r.output)
    assert sorted((d["user"], d["server_name"]) for d in data) == [
        ("alice", "prod-vpn"), ("carol", "prod-vpn"), ("dave", "prod-vpn"),
        ("dave", "staging-vpn")]
    assert all(d["connected"] for d in data)


def test_online_filters_and_negated_terms(fake_api):
    r = run("online", "-o", "json", "-group:dev", "--server", "prod")
    assert sorted(d["user"] for d in json.loads(r.output)) == ["alice", "carol"]


def test_online_summary(fake_api):
    r = run("online", "--summary", "-o", "json")
    rows = {d["server"]: d for d in json.loads(r.output)}
    assert rows["prod-vpn"]["sessions"] == 3
    assert rows["staging-vpn"]["users"] == 1


def test_search_exit_codes(fake_api):
    assert run("search", "alice").exit_code == 0
    assert run("search", "nobody-here").exit_code == 1


def test_search_bad_query(fake_api):
    r = run("search", "nope:1")
    assert r.exit_code == 2


def test_whois(fake_api):
    r = run("whois", "10.8.0.3", "203.0.113.10", "-o", "json")
    data = json.loads(r.output)
    got = sorted((d["query"], d["user"], d["match"]) for d in data)
    assert got == [
        ("10.8.0.3", "bob", "vpn-ip (assigned)"),
        ("10.8.0.3", "erin", "vpn-ip (assigned)"),
        ("203.0.113.10", "alice", "real-ip"),
        ("203.0.113.10", "dave", "real-ip"),
    ]


def test_whois_nothing(fake_api):
    assert run("whois", "192.168.255.255").exit_code == 1


def test_ips_hosts_format(fake_api):
    r = run("ips", "--server", "staging", "--hosts", "--domain", "vpn.example.test")
    assert "10.9.0.2\talice.staging-vpn.vpn.example.test" in r.output
    assert "prod" not in r.output


def test_secrets_never_exposed(fake_api):
    for args in (["search", "-o", "json"], ["orgs", "-o", "json"],
                 ["user", "show", "alice", "-o", "json"], ["config", "show"]):
        out = run(*args).output
        assert "LEAK" not in out
        assert SECRET not in out


def test_terminal_escape_and_markup_stripped(fake_api, monkeypatch):
    from pritunl_toolbox import output
    monkeypatch.setattr(output.console, "width", 250)
    r = run("online", "--server", "prod")
    assert "\x1b" not in r.output
    assert "[red]evil" in r.output  # shown literally, not interpreted as markup


def test_csv_formula_injection_neutralised(fake_api):
    r = run("search", "name:=erin", "-o", "csv")
    rows = list(csv.DictReader(io.StringIO(r.output)))
    assert rows[0]["email"].startswith("'=")


def test_user_show_with_audit(fake_api):
    r = run("user", "show", "alice@example.test", "--audit", "-o", "json")
    data = json.loads(r.output)
    assert data["name"] == "alice"
    assert data["audit"][0]["type"] == "login"


def test_user_show_ambiguous_and_missing(fake_api):
    assert run("user", "show", "nobody").exit_code != 0


def test_no_write_commands_exist(fake_api):
    for args in (["user", "disable", "alice"], ["user", "enable", "alice"]):
        r = CliRunner().invoke(cli, args)
        assert r.exit_code == 2 and "No such command" in r.output
    assert "read-only" in run("--help").output
    assert "read-only" in run("config", "show").output


def test_every_command_is_read_only(fake_api):
    for args in (["status"], ["orgs"], ["servers"], ["hosts"], ["online"], ["search"],
                 ["whois", "10.8.0.3"], ["ips"], ["user", "show", "alice", "--audit"],
                 ["server", "show", "prod"], ["server", "logs", "prod"], ["report"]):
        run(*args)
    assert fake_api.writes == []
    assert {m for m, _ in fake_api.calls} == {"GET"}


def test_report_findings(fake_api):
    r = run("report", "-o", "json")
    assert r.exit_code == 3  # high severity findings present
    checks = {(f["check"], f["subject"]) for f in json.loads(r.output)["findings"]}
    assert ("disabled-user-connected", "Contractors/carol") in checks
    assert ("duplicate-vpn-ip", "prod-vpn 10.8.0.3") in checks
    assert ("multiple-source-ips", "Engineering/dave") in checks
    assert ("bypass-2fa", "Contractors/carol") not in checks  # disabled users are skipped
    assert ("inactive-user", "Engineering/bob") in checks
    assert ("never-active", "Engineering/erin") in checks
    assert ("server-without-2fa", "staging-vpn") in checks


def test_server_show_and_logs(fake_api):
    # live entries carry session ids, not server ids (Pritunl quirk) - must still match
    r = run("server", "show", "prod", "-o", "json")
    data = json.loads(r.output)
    assert {s["user"] for s in data["sessions"]} == {"alice", "carol", "dave"}
    assert all(s["server_id"] == "srv1" and s["session_id"].startswith("sess-")
               for s in data["sessions"])
    r = run("server", "logs", "prod-vpn")
    assert "\x1b" not in r.output and "badred" in r.output.replace("[31m", "")


def test_every_request_uses_fresh_nonce(fake_api):
    run("report", "-o", "json")
    assert len(fake_api.nonces) == len(fake_api.calls) > 3


@pytest.mark.parametrize("cmd", [["servers"], ["hosts"], ["orgs"], ["search", "-x"],
                                 ["report"], ["ips"], ["user", "show", "dave"]])
def test_table_outputs_render(fake_api, cmd):
    r = run(*cmd)
    assert r.exit_code in (0, 3), r.output


def test_online_watch_streams_events(fake_api, monkeypatch):
    import copy

    import conftest

    original = copy.deepcopy(conftest.USERS)
    calls = {"n": 0}

    def fake_sleep(_):
        calls["n"] += 1
        if calls["n"] == 1:
            # carol disconnects between polls
            conftest.USERS["org2"][0]["servers"][0].update(status=False, real_address=None)
        else:
            raise KeyboardInterrupt

    monkeypatch.setattr("pritunl_toolbox.cli.time.sleep", fake_sleep)
    try:
        r = run("online", "--watch", "5", "-o", "json")
    finally:
        conftest.USERS.clear()
        conftest.USERS.update(original)
    events = [json.loads(line) for line in r.output.splitlines()]
    assert r.exit_code == 130
    assert sum(e["event"] == "present" for e in events) == 4
    assert [(e["event"], e["user"]) for e in events if e["event"] != "present"] == [
        ("disconnect", "carol")]
