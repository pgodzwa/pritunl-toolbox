# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 pritunl-toolbox contributors
"""pritunl-toolbox command line interface."""

from __future__ import annotations

import functools
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import click
from rich.text import Text

from pritunl_toolbox import LICENSE_NOTICE, __version__
from pritunl_toolbox.analysis import (
    SESSION_COLUMNS,
    SEVERITY_ORDER,
    USER_COLUMNS,
    build_report,
    hostname_label,
    iter_sessions,
    session_json,
    session_row,
    user_json,
    user_row,
    with_geo,
)
from pritunl_toolbox.api import PritunlAPIError, PritunlClient
from pritunl_toolbox.config import (
    ConfigError,
    default_config_path,
    load_geo_settings,
    load_profile,
    save_geo_settings,
    save_profile,
)
from pritunl_toolbox.context import Ctx
from pritunl_toolbox.geo import GeoError, GeoResolver, resolve_paths
from pritunl_toolbox.geoinstall import GeoInstallError
from pritunl_toolbox.inventory import Inventory
from pritunl_toolbox.models import Host, Organization, Server, User
from pritunl_toolbox.output import (
    FORMATS,
    console,
    emit,
    error,
    fmt_ago,
    fmt_duration,
    fmt_ts,
    iso_ts,
    kv_table,
    render_json,
    sanitize,
    warn,
)
from pritunl_toolbox.query import Query, QueryError
from pritunl_toolbox.travel import (
    DEFAULT_MAX_SPEED_KMH,
    DEFAULT_MIN_DISTANCE_KM,
    audit_observations,
    detect,
    session_observations,
)

# ----------------------------------------------------------------------------- plumbing


pass_ctx = click.make_pass_decorator(Ctx)


def handle_errors(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (ConfigError, PritunlAPIError, QueryError, GeoError, GeoInstallError) as exc:
            error(str(exc))
            sys.exit(2)
        except KeyboardInterrupt:
            sys.exit(130)
    return wrapper


def output_option(func):
    return click.option("-o", "--output", "fmt", type=click.Choice(FORMATS), default="table",
                        show_default=True, help="Output format.")(func)


QUERY_HELP = """
\b
QUERY terms (all must match; prefix with '-' to negate, e.g. -group:contractors):
  10.8.0.15 / 10.8.0.0/24   bare IP or CIDR: VPN IP or real IP
  vip:IP  rip:IP  ip:IP     VPN (virtual) IP / real (public) IP / either
  name:  email:  id:  org:  group:  server:  platform:  device:  type:  auth:
  status:online|offline|disabled|enabled   connected:yes|no
  inactive:90d  active:24h  bypass2fa:yes  pin:yes
  country:PL,DE  city:berlin  asn:13335  asn:~hetzner   (needs a GeoIP database)
\b
Values: foo (substring)  =foo (exact)  fo* (glob)  ~regex  a,b (any of)
"""


def query_options(func):
    """Convenience flags that are translated into query terms."""
    opts = [
        click.option("--vpn-ip", "vip", multiple=True, help="VPN IP or CIDR."),
        click.option("--real-ip", "rip", multiple=True, help="Real/public IP or CIDR."),
        click.option("--group", "-g", multiple=True, help="Group (repeat for AND)."),
        click.option("--server", "-s", multiple=True, help="Server name (substring/glob)."),
        click.option("--org", multiple=True, help="Organization name."),
        click.option("--online", is_flag=True, help="Only users/sessions currently connected."),
        click.option("--offline", is_flag=True, help="Only users not connected."),
        click.option("--disabled", is_flag=True, help="Only disabled users."),
    ]
    for opt in reversed(opts):
        func = opt(func)
    return func


def build_query(terms: tuple[str, ...], vip=(), rip=(), group=(), server=(), org=(),
                online=False, offline=False, disabled=False) -> Query:
    parts = list(terms)
    parts += [f"vip:{v}" for v in vip] + [f"rip:{v}" for v in rip]
    parts += [f"group:{_q(v)}" for v in group] + [f"server:{_q(v)}" for v in server]
    parts += [f"org:{_q(v)}" for v in org]
    if online:
        parts.append("status:online")
    if offline:
        parts.append("status:offline")
    if disabled:
        parts.append("status:disabled")
    return Query.parse(parts)


# A negated query term (-group:x, -10.0.0.1, -fd00::1) would otherwise be parsed by click as a
# short option cluster (-g roup:x). Such arguments are moved behind '--' before parsing; terms
# are AND-ed so their order does not matter.
_NEG_TERM = re.compile(r"^-(?:[A-Za-z_]\w*:|\d|[0-9a-fA-F]{1,4}:)")


class QueryCommand(click.Command):
    def parse_args(self, ctx, args):
        if "--" in args:
            idx = args.index("--")
            head, tail = args[:idx], args[idx:]
        else:
            head, tail = args, []
        negated = [a for a in head if _NEG_TERM.match(a)]
        if negated:
            head = [a for a in head if not _NEG_TERM.match(a)]
            tail = (tail or ["--"]) + negated
        return super().parse_args(ctx, head + tail)


def require_geo(c: Ctx, query: Query) -> Query:
    if query.uses_geo and c.geo is None:
        raise GeoError("country:/city:/asn: terms need a GeoIP database "
                       "(see 'pritunl-toolbox geo status')")
    return query


def _q(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"' if any(c.isspace() for c in value) else value


def _sort_sessions(pairs):
    return sorted(pairs, key=lambda p: (p[1].server_name.lower(), p[0].org_name.lower(),
                                        p[0].name.lower()))


# ----------------------------------------------------------------------------- root


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="pritunl-toolbox",
                      message="%(prog)s, version %(version)s\n" + LICENSE_NOTICE)
@click.option("-p", "--profile", "profile_name", envvar="PRITUNL_PROFILE",
              help="Config profile to use.")
@click.option("--url", help="Override Pritunl URL.")
@click.option("--ca-bundle", type=click.Path(exists=True, dir_okay=False),
              help="CA bundle for a private/self-signed Pritunl certificate.")
@click.option("--insecure", is_flag=True,
              help="Disable TLS verification (dangerous; prefer --ca-bundle).")
@click.option("--timeout", type=float, help="HTTP timeout in seconds.")
@click.option("--workers", type=click.IntRange(1, 16), help="Parallel API requests.")
@click.option("--geo/--no-geo", "geo_mode", default=None,
              help="Force / disable offline GeoIP enrichment (default: auto-detect database).")
@click.pass_context
def cli(ctx, profile_name, url, ca_bundle, insecure, timeout, workers, geo_mode):
    """Toolbox for Pritunl VPN: who is connected, who owns an IP, user search and audits.

    Strictly read-only: it never changes anything on the Pritunl server.

    \b
    Quick start:
      pritunl-toolbox config init
      pritunl-toolbox online
      pritunl-toolbox whois 10.8.0.15
      pritunl-toolbox search group:devops status:online
      pritunl-toolbox tui                  interactive terminal UI
    """
    overrides = {"url": url, "ca_bundle": ca_bundle, "timeout": timeout, "workers": workers}
    if insecure:
        overrides["verify_tls"] = False
    ctx.obj = Ctx(profile_name, overrides, geo_mode=geo_mode)


# ----------------------------------------------------------------------------- config


@cli.group()
def config():
    """Manage connection profiles."""


@config.command("init")
@click.option("--name", default="default", show_default=True, help="Profile name.")
@click.option("--url", prompt="Pritunl URL (e.g. https://vpn.example.com)")
@click.option("--token", prompt="API token")
@click.option("--ca-bundle", default=None, help="Path to CA bundle for private CAs.")
@click.option("--secret-cmd", default=None,
              help="Command printing the API secret (e.g. 'pass show pritunl'); "
                   "if set the secret is not stored in the file.")
@click.option("--default/--no-default", "make_default", default=True,
              help="Make this the default profile.")
@handle_errors
def config_init(name, url, token, ca_bundle, secret_cmd, make_default):
    """Create or update a profile (secret is prompted, never passed on argv).

    The toolbox only ever reads from Pritunl, so a dedicated administrator with API access
    is enough; nothing is changed on the server.
    """
    values: dict[str, Any] = {"url": url.rstrip("/"), "api_token": token, "verify_tls": True}
    if ca_bundle:
        values["ca_bundle"] = ca_bundle
    if secret_cmd:
        values["api_secret_cmd"] = secret_cmd
    else:
        values["api_secret"] = click.prompt("API secret", hide_input=True)
    path = save_profile(name, values, make_default=make_default)
    console.print(Text(f"Saved profile '{name}' to {path} (mode 600)."))
    if click.confirm("Test the connection now?", default=True):
        prof = load_profile(name, path=path, warn=warn)
        status = PritunlClient(prof).status()
        console.print(Text(f"OK: Pritunl {sanitize(status.get('server_version', '?'))}, "
                           f"{status.get('user_count', '?')} users", style="green"))


@config.command("show")
@pass_ctx
@handle_errors
def config_show(c: Ctx):
    """Show the active profile (secrets redacted)."""
    kv_table(c.profile.describe().items(), title=f"config: {default_config_path()}")


@config.command("test")
@pass_ctx
@handle_errors
def config_test(c: Ctx):
    """Check connectivity and API credentials."""
    t0 = time.time()
    status = c.client.status()
    console.print(Text(
        f"OK {c.profile.url}: Pritunl {sanitize(status.get('server_version', '?'))} "
        f"({(time.time() - t0) * 1000:.0f} ms)", style="green"))


# ----------------------------------------------------------------------------- overview


@cli.command()
@output_option
@pass_ctx
@handle_errors
def status(c: Ctx, fmt):
    """Global status: users/servers/hosts online."""
    st = c.client.status()
    keys = ["server_version", "org_count", "user_count", "users_online", "server_count",
            "servers_online", "host_count", "hosts_online", "public_ip", "current_host"]
    data = {k: st.get(k) for k in keys if k in st}
    if fmt == "table":
        kv_table(data.items(), title=f"Pritunl {c.profile.url}")
    else:
        emit([data], [(k, k) for k in data], fmt, json_data=data)


@cli.command()
@output_option
@pass_ctx
@handle_errors
def orgs(c: Ctx, fmt):
    """List organizations (org API credentials are never shown)."""
    rows = [Organization.from_api(o) for o in c.client.organizations()]
    emit([vars(o) for o in rows], [("name", "Name"), ("id", "ID"), ("user_count", "Users")],
         fmt, title="Organizations")


@cli.command()
@output_option
@click.option("--status", "status_filter", type=click.Choice(["online", "offline", "pending"]))
@pass_ctx
@handle_errors
def servers(c: Ctx, fmt, status_filter):
    """List servers with live session counts."""
    items = [Server.from_api(s) for s in c.client.servers()]
    if status_filter:
        items = [s for s in items if s.status == status_filter]
    rows = [{**vars(s), "uptime": fmt_duration(s.uptime) if s.uptime else "",
             "listen": f"{s.protocol or ''}/{s.port or ''}",
             "2fa": "otp" if s.otp_auth else ("sso" if s.sso_auth else "no")} for s in items]
    cols = [("name", "Name"), ("status", "Status"), ("users_online", "Users"),
            ("devices_online", "Devices"), ("user_count", "Total"), ("network", "Network"),
            ("listen", "Listen"), ("groups", "Groups"), ("2fa", "2FA"), ("uptime", "Uptime")]
    emit(rows, cols, fmt, title="Servers", json_data=[vars(s) for s in items])


@cli.command()
@output_option
@pass_ctx
@handle_errors
def hosts(c: Ctx, fmt):
    """List Pritunl hosts."""
    items = [Host.from_api(h) for h in c.client.hosts()]
    rows = [{**vars(h), "uptime": fmt_duration(h.uptime) if h.uptime else ""} for h in items]
    cols = [("name", "Name"), ("hostname", "Hostname"), ("status", "Status"),
            ("public_addr", "Public"), ("local_addr", "Local"), ("version", "Version"),
            ("uptime", "Uptime")]
    emit(rows, cols, fmt, title="Hosts", json_data=[vars(h) for h in items])


# ----------------------------------------------------------------------------- sessions


def _session_key(u: User, e) -> tuple:
    return (u.id, e.server_id, e.session_id, e.real_address, e.virt_address, e.connected_since)


@cli.command(cls=QueryCommand)
@click.argument("terms", nargs=-1, type=click.UNPROCESSED)
@query_options
@output_option
@click.option("--summary", is_flag=True, help="Only print per-server session counts.")
@click.option("--watch", type=click.IntRange(min=5), metavar="SECONDS",
              help="Keep polling and print connect/disconnect events.")
@pass_ctx
@handle_errors
def online(c: Ctx, terms, fmt, summary, watch, **flags):
    """Show who is connected right now (one row per session).

    Accepts the same QUERY terms as 'search', e.g.: online server:prod group:devops
    """
    flags["online"] = True
    query = require_geo(c, build_query(terms, **flags))

    def snapshot():
        inv = c.inventory()
        pairs = [(m.user, e) for m in query.run(inv.users) for e in m.entries if e.connected]
        return _sort_sessions(pairs)

    pairs = snapshot()
    if watch and fmt == "json":
        # Stream mode: JSON lines, starting with the sessions that already exist.
        for u, e in pairs:
            _print_event("present", u, e, fmt)
    elif summary:
        counts: dict[str, set] = {}
        for u, e in pairs:
            counts.setdefault(e.server_name, set()).add(u.id)
        rows = [{"server": s, "sessions": sum(1 for _, e in pairs if e.server_name == s),
                 "users": len(ids)} for s, ids in sorted(counts.items())]
        emit(rows, [("server", "Server"), ("sessions", "Sessions"), ("users", "Users")], fmt,
             title=f"Online: {len(pairs)} sessions")
    elif fmt == "json":
        render_json([session_json(u, e) for u, e in pairs])
    else:
        now = time.time()
        emit([session_row(u, e, now) for u, e in pairs],
             with_geo(SESSION_COLUMNS, c.geo is not None), fmt,
             title=f"Online sessions: {len(pairs)} ({len({u.id for u, _ in pairs})} users)")
    if not watch:
        return

    known = {_session_key(u, e): (u, e) for u, e in pairs}
    if fmt != "json":
        console.print(Text(f"watching every {watch}s, Ctrl+C to stop", style="dim"))
    while True:
        time.sleep(watch)
        try:
            current = {_session_key(u, e): (u, e) for u, e in snapshot()}
        except PritunlAPIError as exc:
            warn(f"poll failed: {exc}")
            continue
        events = [("connect", current[k]) for k in current.keys() - known.keys()]
        events += [("disconnect", known[k]) for k in known.keys() - current.keys()]
        for kind, (u, e) in sorted(events, key=lambda ev: ev[1][0].name):
            _print_event(kind, u, e, fmt)
        known = current


def _print_event(kind: str, u: User, e, fmt: str) -> None:
    ts = time.time()
    if fmt == "json":
        sys.stdout.write(json.dumps({"event": kind, "time": iso_ts(ts), **session_json(u, e)},
                                    default=str) + "\n")
        sys.stdout.flush()
        return
    style = "green" if kind == "connect" else "red"
    line = Text(time.strftime("%H:%M:%S "), style="dim")
    line += Text(f"{kind.upper():<10}", style=style)
    where = f" [{e.geo.label}, {e.geo.asn_label}]" if e.geo else ""
    line += Text(sanitize(f" {u.org_name}/{u.name} -> {e.server_name} vpn={e.virt_address} "
                          f"real={e.real_address}{where} device={e.device_name or '-'} "
                          f"({e.platform or '-'})"))
    console.print(line)


@cli.command(cls=QueryCommand, epilog=QUERY_HELP)
@click.argument("terms", nargs=-1, type=click.UNPROCESSED)
@query_options
@output_option
@click.option("-x", "--expand", is_flag=True, help="One row per matching server entry.")
@click.option("--limit", type=int, default=0, help="Show at most N results.")
@pass_ctx
@handle_errors
def search(c: Ctx, terms, fmt, expand, limit, **flags):
    """Search users by name, email, group, VPN IP, real IP, server, status...

    \b
    Examples:
      search john                         free text (name/email/id/org/group)
      search 10.8.0.15                    who has / is using this IP
      search rip:203.0.113.0/24 --online  sessions from a public range
      search group:devops,sre -status:disabled
      search server:prod-* platform:win
      search inactive:90d status:enabled  stale accounts
      search -country:PL --online         (with GeoIP) sessions from abroad
    """
    query = require_geo(c, build_query(terms, **flags))
    inv = c.inventory()
    matches = query.run(inv.users)
    matches.sort(key=lambda m: (m.user.org_name.lower(), m.user.name.lower()))
    total = len(matches)
    if limit:
        matches = matches[:limit]
    now = time.time()
    if fmt == "json":
        render_json([user_json(m.user, m.entries) for m in matches])
    elif expand:
        rows = [session_row(m.user, e, now) for m in matches for e in m.entries]
        emit(rows, with_geo(SESSION_COLUMNS, c.geo is not None), fmt,
             title=f"{total} users match: {query}")
    else:
        emit([user_row(m, now) for m in matches], with_geo(USER_COLUMNS, c.geo is not None), fmt,
             title=f"{total} users match: {query}")
    if not matches:
        sys.exit(1)


@cli.command()
@click.argument("ips", nargs=-1, required=True)
@output_option
@pass_ctx
@handle_errors
def whois(c: Ctx, ips, fmt):
    """Who owns / uses an IP? Checks VPN IPs (assigned + live) and real IPs.

    Accepts single IPs or CIDR ranges. Exit code 1 if nothing matched.
    """
    inv = c.inventory()
    now = time.time()
    rows: list[dict] = []
    data: list[dict] = []
    for ip in ips:
        query = Query.parse([f"ip:{ip}"])
        vip_q = Query.parse([f"vip:{ip}"])
        for m in query.run(inv.users):
            for e in m.entries:
                is_vip = vip_q.entry_terms[0].entry_pred(e)
                kind = ("vpn-ip (live)" if e.connected else "vpn-ip (assigned)") if is_vip \
                    else "real-ip"
                rows.append({"query": ip, "match": kind, **session_row(m.user, e, now)})
                data.append({"query": ip, "match": kind, **session_json(m.user, e)})
    cols = [("query", "Query"), ("match", "Match"), ("org", "Org"), ("user", "User"),
            ("email", "Email"), ("server", "Server"), ("state", "State"), ("vpn_ip", "VPN IP"),
            ("real_ip", "Real IP"), ("uptime", "Connected"), ("device", "Device")]
    cols = with_geo(cols, c.geo is not None)
    if fmt == "json":
        render_json(data)
    else:
        emit(rows, cols, fmt, title="whois")
    if not rows:
        if fmt == "table":
            warn("no user has or uses that address")
        sys.exit(1)


@cli.command(cls=QueryCommand)
@click.argument("terms", nargs=-1, type=click.UNPROCESSED)
@query_options
@output_option
@click.option("--hosts", "hosts_fmt", is_flag=True,
              help="Print /etc/hosts style lines: '<vpn-ip> <user>.<server>'.")
@click.option("--domain", default="", help="Suffix for --hosts names, e.g. vpn.example.com.")
@pass_ctx
@handle_errors
def ips(c: Ctx, terms, fmt, hosts_fmt, domain, **flags):
    """Export the user -> VPN IP assignment map (for firewalls, DNS, inventories)."""
    query = require_geo(c, build_query(terms, **flags))
    inv = c.inventory()
    rows = []
    for m in sorted(query.run(inv.users), key=lambda m: (m.user.org_name, m.user.name)):
        entries = m.entries if query.has_entry_terms else m.user.servers
        for e in entries:
            if not (e.virt_address or e.virt_address6):
                continue
            rows.append({"server": e.server_name, "org": m.user.org_name,
                         "user": m.user.name, "email": m.user.email,
                         "groups": m.user.groups, "vpn_ip": e.virt_address,
                         "vpn_ip6": e.virt_address6, "connected": e.connected,
                         "disabled": m.user.disabled})
    rows.sort(key=lambda r: (r["server"], r["vpn_ip"] or ""))
    if hosts_fmt:
        suffix = "." + domain.strip(".") if domain else ""
        for r in rows:
            name = f"{hostname_label(r['user'])}.{hostname_label(r['server'])}{suffix}"
            for ip in (r["vpn_ip"], r["vpn_ip6"]):
                if ip:
                    click.echo(f"{ip}\t{name}")
        return
    cols = [("server", "Server"), ("vpn_ip", "VPN IP"), ("vpn_ip6", "VPN IPv6"),
            ("org", "Org"), ("user", "User"), ("email", "Email"), ("groups", "Groups"),
            ("connected", "Online")]
    emit(rows, cols, fmt, title=f"{len(rows)} VPN address assignments")


# ----------------------------------------------------------------------------- user


@cli.group()
def user():
    """Inspect single users (read-only)."""


def _resolve_user(c: Ctx, ident: str, org: str | None) -> tuple[Inventory, User]:
    inv = c.inventory(org_filter=org)
    found = inv.find_users(ident)
    if not found:
        raise click.ClickException(f"no user matches '{ident}' (try 'search {ident}')")
    if len(found) > 1:
        lines = "\n".join(f"  {u.org_name}/{u.name} <{u.email or ''}> id={u.id}" for u in found)
        raise click.ClickException(
            f"'{ident}' is ambiguous, narrow it with --org or use the id:\n{lines}")
    return inv, found[0]


@user.command("show")
@click.argument("ident")
@click.option("--org", help="Organization (if the name exists in several).")
@click.option("--audit", is_flag=True, help="Include the user's audit log.")
@output_option
@pass_ctx
@handle_errors
def user_show(c: Ctx, ident, org, audit, fmt):
    """Show a user (by id, name or email) with assigned IPs and live sessions."""
    _, u = _resolve_user(c, ident, org)
    audit_rows = []
    if audit:
        for a in c.client.user_audit(u.org_id, u.id):
            audit_rows.append({
                "time": fmt_ts(a.get("timestamp")),
                "type": a.get("type"),
                "remote_addr": a.get("remote_addr") or a.get("remote_address"),
                "message": a.get("message"),
            })
    if fmt == "json":
        data = user_json(u)
        if audit:
            data["audit"] = audit_rows
        render_json(data)
        return
    now = time.time()
    if fmt == "csv":
        emit([session_row(u, e, now) for e in u.servers], SESSION_COLUMNS, fmt)
        return
    kv_table([
        ("Name", u.name), ("Email", u.email), ("ID", u.id), ("Organization", u.org_name),
        ("Groups", u.groups), ("State", u.state), ("Type", u.type), ("Auth", u.auth_type),
        ("Bypass 2FA", u.bypass_secondary), ("PIN set", u.pin),
        ("Last active", f"{fmt_ts(u.last_active)} ({fmt_ago(u.last_active, now)})"
         if u.last_active else "never"),
    ], title="User")
    emit([session_row(u, e, now) for e in u.servers],
         with_geo([c_ for c_ in SESSION_COLUMNS if c_[0] not in ("org", "user", "groups")],
                  c.geo is not None),
         "table", title="Servers")
    if audit:
        emit(audit_rows, [("time", "Time"), ("type", "Type"), ("remote_addr", "Remote"),
                          ("message", "Message")], "table", title="Audit log")


# ----------------------------------------------------------------------------- server


@cli.group()
def server():
    """Inspect a single server."""


def _resolve_server(c: Ctx, ref: str) -> Server:
    items = [Server.from_api(s) for s in c.client.servers()]
    inv = Inventory(servers=items)
    found = inv.server_by_ref(ref)
    if not found:
        raise click.ClickException(f"no server matches '{ref}'")
    if len(found) > 1:
        raise click.ClickException(
            f"'{ref}' is ambiguous: " + ", ".join(s.name for s in found))
    return found[0]


@server.command("show")
@click.argument("ref")
@output_option
@pass_ctx
@handle_errors
def server_show(c: Ctx, ref, fmt):
    """Server details, attached orgs, routes, hosts and connected users."""
    s = _resolve_server(c, ref)
    orgs_ = c.client.server_orgs(s.id)
    routes = c.client.server_routes(s.id)
    hosts_ = c.client.server_hosts(s.id)
    inv = c.inventory()
    pairs = _sort_sessions((u, e) for u, e in iter_sessions(inv.users) if e.server_id == s.id)
    if fmt == "json":
        render_json({
            "server": vars(s),
            "organizations": [Organization.from_api(o).__dict__ for o in orgs_],
            "routes": [{k: r.get(k) for k in ("network", "comment", "nat", "virtual_network")}
                       for r in routes],
            "hosts": [{k: h.get(k) for k in ("id", "name", "status", "address")}
                      for h in hosts_],
            "sessions": [session_json(u, e) for u, e in pairs],
        })
        return
    kv_table([
        ("Name", s.name), ("ID", s.id), ("Status", s.status),
        ("Uptime", fmt_duration(s.uptime) if s.uptime else ""),
        ("Network", s.network), ("Network6", s.network6),
        ("Listen", f"{s.protocol}/{s.port}"),
        ("WireGuard", f"{s.network_wg} :{s.port_wg}" if s.wg else "no"),
        ("Groups", s.groups or "(all)"), ("OTP", s.otp_auth), ("SSO", s.sso_auth),
        ("Organizations", [o.get("name") for o in orgs_]),
        ("Hosts", [f"{h.get('name')} ({h.get('status')})" for h in hosts_]),
        ("Users online", f"{len({u.id for u, _ in pairs})} ({len(pairs)} sessions)"),
    ], title="Server")
    if routes:
        emit([{"network": r.get("network"), "comment": r.get("comment"),
               "nat": r.get("nat")} for r in routes],
             [("network", "Network"), ("nat", "NAT"), ("comment", "Comment")], "table",
             title="Routes")
    now = time.time()
    emit([session_row(u, e, now) for u, e in pairs],
         with_geo([c_ for c_ in SESSION_COLUMNS if c_[0] not in ("server", "state")],
                  c.geo is not None), fmt,
         title="Connected users")


@server.command("logs")
@click.argument("ref")
@click.option("-n", "--tail", type=int, default=50, show_default=True, help="Last N lines.")
@pass_ctx
@handle_errors
def server_logs(c: Ctx, ref, tail):
    """Print the server's process output (OpenVPN/WireGuard log)."""
    s = _resolve_server(c, ref)
    lines = c.client.server_output(s.id)
    for line in lines[-tail:] if tail else lines:
        click.echo(sanitize(line))


# ----------------------------------------------------------------------------- report


def _country_set(value: str | None) -> set[str] | None:
    if not value:
        return None
    codes = {v.strip().upper() for v in value.split(",") if v.strip()}
    bad = [v for v in codes if not re.fullmatch(r"[A-Z]{2}", v)]
    if bad:
        raise click.BadParameter(f"expected ISO country codes like PL,DE; got {', '.join(bad)}")
    return codes


@cli.command()
@output_option
@click.option("--inactive-days", type=int, default=90, show_default=True,
              help="Flag enabled users inactive for longer than this.")
@click.option("--min-severity", type=click.Choice(["high", "medium", "low", "info"]),
              default="info", show_default=True)
@click.option("--allowed-countries", envvar="PRITUNL_ALLOWED_COUNTRIES", metavar="CC,CC",
              help="Flag sessions from other countries (needs GeoIP), e.g. PL,DE,NL.")
@click.option("--max-speed", type=float, default=DEFAULT_MAX_SPEED_KMH, show_default=True,
              help="Impossible-travel speed threshold in km/h (needs GeoIP).")
@click.option("--min-distance", type=float, default=DEFAULT_MIN_DISTANCE_KM, show_default=True,
              help="Ignore location changes shorter than this (km).")
@pass_ctx
@handle_errors
def report(c: Ctx, fmt, inactive_days, min_severity, allowed_countries, max_speed,
           min_distance):
    """Health & security report: sessions per server, groups, and findings.

    Findings include disabled users still connected, accounts used from several IPs at once,
    duplicate VPN IPs, users bypassing 2FA, stale accounts and servers without 2FA. With a
    GeoIP database also impossible travel and sessions from unexpected countries.
    Exit code 3 if any high severity finding exists (useful in cron/CI).
    """
    allowed = _country_set(allowed_countries)
    if allowed and c.geo is None:
        raise GeoError("--allowed-countries needs a GeoIP database (see 'geo status')")
    inv = c.inventory()
    events = detect(session_observations(inv.users), max_speed, min_distance) if c.geo else []
    rep = build_report(inv, inactive_days=inactive_days, allowed_countries=allowed,
                       travel_events=events)
    limit = SEVERITY_ORDER[min_severity]
    rep["findings"] = [f for f in rep["findings"] if SEVERITY_ORDER[f["severity"]] <= limit]
    if fmt == "json":
        render_json(rep)
    elif fmt == "csv":
        emit(rep["findings"], [("severity", "severity"), ("check", "check"),
                               ("subject", "subject"), ("detail", "detail")], "csv")
    else:
        ov = rep["overview"]
        kv_table([(k.replace("_", " ").capitalize(), v if not isinstance(v, dict)
                   else [f"{p}: {n}" for p, n in v.items()]) for k, v in ov.items()],
                 title="Overview")
        emit(rep["servers"], [("server", "Server"), ("status", "Status"),
                              ("sessions", "Sessions"), ("users", "Users"),
                              ("platforms", "Platforms")], "table", title="Servers")
        emit(rep["groups"][:25], [("group", "Group"), ("users", "Users"),
                                  ("online", "Online")], "table", title="Groups (top 25)")
        if rep["countries"]:
            emit(rep["countries"], [("country", "Country"), ("sessions", "Sessions")], "table",
                 title="Sessions by country")
        emit(rep["findings"], [("severity", "Severity"), ("check", "Check"),
                               ("subject", "Subject"), ("detail", "Detail")], "table",
             title=f"Findings ({len(rep['findings'])})")
    if any(f["severity"] == "high" for f in rep["findings"]):
        sys.exit(3)


# ----------------------------------------------------------------------------- travel


TRAVEL_COLUMNS = [
    ("user", "User"), ("from_time", "From (time)"), ("from_ip", "From IP"),
    ("from_loc", "From"), ("to_time", "To (time)"), ("to_ip", "To IP"), ("to_loc", "To"),
    ("distance", "Distance"), ("elapsed", "Elapsed"), ("speed", "Speed"),
]


def travel_row(ev) -> dict[str, Any]:
    return {
        "user": ev.user,
        "from_time": fmt_ts(ev.start.ts), "from_ip": ev.start.ip,
        "from_loc": f"{ev.start.geo.label} / {ev.start.geo.asn_label}",
        "to_time": fmt_ts(ev.end.ts), "to_ip": ev.end.ip,
        "to_loc": f"{ev.end.geo.label} / {ev.end.geo.asn_label}",
        "distance": f"{ev.distance_km:,.0f} km",
        "elapsed": "concurrent" if ev.concurrent else fmt_duration(ev.hours * 3600),
        "speed": "∞" if ev.concurrent else f"{ev.speed_kmh:,.0f} km/h",
    }


@cli.command(cls=QueryCommand)
@click.argument("terms", nargs=-1, type=click.UNPROCESSED)
@output_option
@click.option("--audit", "use_audit", is_flag=True,
              help="Also use the Pritunl audit log (needs auditing enabled on the server).")
@click.option("--days", type=click.IntRange(1, 365), default=7, show_default=True,
              help="History window for --audit.")
@click.option("--max-users", type=click.IntRange(1, 5000), default=200, show_default=True,
              help="Cap on users whose audit log is fetched (one API call each).")
@click.option("--max-speed", type=float, default=DEFAULT_MAX_SPEED_KMH, show_default=True,
              help="km/h above which travel is considered impossible.")
@click.option("--min-distance", type=float, default=DEFAULT_MIN_DISTANCE_KM, show_default=True,
              help="Ignore location changes shorter than this (km).")
@pass_ctx
@handle_errors
def travel(c: Ctx, terms, fmt, use_audit, days, max_users, max_speed, min_distance):
    """Detect impossible travel (needs a GeoIP database).

    Compares where each user's sessions come from. Live sessions alone catch the same account
    being used from far-apart places at once. --audit adds the history recorded in Pritunl's
    audit log. Optional QUERY terms select users (default: everyone).
    Exit code 3 if anything is detected.

    \b
    Examples:
      travel
      travel --audit --days 30 group:admins
    """
    from concurrent.futures import ThreadPoolExecutor

    if c.geo is None:
        raise GeoError("impossible-travel detection needs a GeoIP database (see 'geo status')")
    query = require_geo(c, Query.parse(terms))
    inv = c.inventory()
    users = [m.user for m in query.run(inv.users)]
    now = time.time()
    observations = session_observations(users, now)
    if use_audit:
        since = now - days * 86400
        candidates = sorted((u for u in users if u.last_active and u.last_active >= since),
                            key=lambda u: -(u.last_active or 0))
        if len(candidates) > max_users:
            warn(f"{len(candidates)} users active in the window; checking the {max_users} most "
                 "recently active (raise --max-users or narrow with query terms)")
            candidates = candidates[:max_users]

        def fetch(u: User):
            try:
                return u, c.client.user_audit(u.org_id, u.id)
            except PritunlAPIError as exc:
                warn(f"audit log for {u.org_name}/{u.name} unavailable: {exc}")
                return u, []

        with ThreadPoolExecutor(max_workers=c.profile.workers) as pool:
            for u, audit in pool.map(fetch, candidates):
                observations += audit_observations(u, audit, c.geo, since)
    events = detect(observations, max_speed, min_distance)
    if fmt == "json":
        render_json([e.as_dict() for e in events])
    else:
        emit([travel_row(e) for e in events], TRAVEL_COLUMNS, fmt,
             title=f"Impossible travel: {len(events)} event(s) "
                   f"(> {max_speed:,.0f} km/h, > {min_distance:,.0f} km)")
    if events:
        sys.exit(3)


# ----------------------------------------------------------------------------- geo


@cli.group()
def geo():
    """Offline GeoIP / ASN databases (no IP ever leaves this machine)."""


GEO_HELP = """No GeoIP database found. Options (all offline, no API calls per lookup):
  * Easiest: run 'pritunl-toolbox geo setup' - a wizard that downloads MaxMind GeoLite2
    (free account) and configures everything.
  * MaxMind GeoLite2 (free account): install 'geoipupdate', set EditionIDs to
    'GeoLite2-City GeoLite2-ASN' and run it weekly (files land in /usr/share/GeoIP).
  * DB-IP lite (no account): download dbip-city-lite and dbip-asn-lite .mmdb files
    into ~/.local/share/GeoIP/
  * Or point the config at the files:
        [geoip]
        city = "/path/GeoLite2-City.mmdb"
        asn  = "/path/GeoLite2-ASN.mmdb"
"""


@geo.command("status")
@pass_ctx
@handle_errors
def geo_status(c: Ctx):
    """Show which GeoIP databases are used."""
    city, asn = resolve_paths(load_geo_settings())
    if not city and not asn:
        click.echo(GEO_HELP)
        sys.exit(1)
    resolver = GeoResolver.open(city, asn)
    rows = [{**d, "built": fmt_ts(d["build_epoch"]),
             "age": fmt_ago(d["build_epoch"])} for d in resolver.describe()]
    emit(rows, [("role", "Role"), ("type", "Type"), ("path", "Path"), ("built", "Built"),
                ("age", "Age")], "table", title="GeoIP databases")
    stale = [r for r in resolver.describe() if time.time() - r["build_epoch"] > 45 * 86400]
    if stale:
        warn("GeoIP data is older than 45 days; refresh it (e.g. run geoipupdate)")


@geo.command("lookup")
@click.argument("ips", nargs=-1, required=True)
@output_option
@pass_ctx
@handle_errors
def geo_lookup(c: Ctx, ips, fmt):
    """Look up IPs in the local GeoIP databases."""
    if c.geo is None:
        raise GeoError("no GeoIP database found (see 'geo status')")
    rows = []
    for ip in ips:
        info = c.geo.lookup(ip)
        if info is None:
            rows.append({"ip": ip, "location": "not found"})
            continue
        rows.append({"ip": ip, "location": info.label, "country": info.country_name,
                     "asn": info.asn_label, "lat": info.latitude, "lon": info.longitude,
                     "accuracy_km": info.accuracy_km})
    emit(rows, [("ip", "IP"), ("location", "Location"), ("country", "Country"),
                ("asn", "ASN"), ("lat", "Lat"), ("lon", "Lon"), ("accuracy_km", "± km")],
         fmt, title="GeoIP lookup")


def _progress_printer(quiet: bool):
    last: dict[str, int] = {}

    def progress(edition: str, done: int, total: int | None) -> None:
        if quiet:
            return
        pct = int(done * 100 / total) if total else None
        step = (pct // 10) if pct is not None else done // (10 * 1024 * 1024)
        if last.get(edition) != step:
            last[edition] = step
            shown = f"{pct}%" if pct is not None else f"{done // 1024 // 1024} MB"
            click.echo(f"  {edition}: {shown}", err=True)

    return progress


@geo.command("setup")
@click.option("--dir", "install_dir", type=click.Path(file_okay=False, path_type=Path),
              help="Where to put the databases (default: ~/.local/share/GeoIP).")
@pass_ctx
@handle_errors
def geo_setup(c: Ctx, install_dir):
    """Wizard: download MaxMind GeoLite2 databases and configure GeoIP.

    Only talks to MaxMind over HTTPS; nothing is sent to or changed on the Pritunl server.
    The license key is prompted (hidden) or read from PRITUNL_MAXMIND_LICENSE_KEY - never
    passed on the command line.
    """
    from pritunl_toolbox import geoinstall as gi

    settings = load_geo_settings()
    click.echo(f"""
GeoLite2 setup
==============
MaxMind's free GeoLite2 databases add country, city and provider (ASN) to connection IPs.
Lookups then happen locally; no IP address is ever sent anywhere.

You need a free MaxMind account and a license key:
  1. Sign up:              {gi.SIGNUP_URL}
  2. Create a license key: {gi.LICENSE_KEY_URL}
     (Account ID is shown on that page; the key is displayed only once.)
""")
    existing = None
    try:
        existing = gi.load_credentials(settings)
    except (gi.GeoInstallError, ConfigError) as exc:
        warn(f"ignoring stored MaxMind credentials: {exc}")
    if existing and click.confirm(f"Use stored credentials for account {existing.account_id}?",
                                  default=True):
        creds = existing
    else:
        account = click.prompt("MaxMind account ID",
                               value_proc=gi.validate_account_id_click)
        key = os.environ.get("PRITUNL_MAXMIND_LICENSE_KEY") or click.prompt(
            "License key (hidden)", hide_input=True, value_proc=gi.validate_license_key_click)
        creds = gi.Credentials(account, gi.validate_license_key(key))

    click.echo("\nDatabases:")
    editions = []
    if click.confirm("  GeoLite2-City  (country + city + coordinates, ~60 MB; needed for "
                     "impossible travel)", default=True):
        editions.append("GeoLite2-City")
    elif click.confirm("  GeoLite2-Country (country only, ~10 MB)", default=True):
        editions.append("GeoLite2-Country")
    if click.confirm("  GeoLite2-ASN   (network provider, ~10 MB)", default=True):
        editions.append("GeoLite2-ASN")
    if not editions:
        raise click.ClickException("nothing selected")

    default_dir = install_dir or Path(settings.get("dir") or gi.default_install_dir())
    dest = Path(click.prompt("Install directory", default=str(default_dir))).expanduser()

    click.echo("""
Store the credentials so 'pritunl-toolbox geo update' can refresh the data later?
  config  - in the config file (mode 600)
  command - run a password-manager command instead, e.g. 'pass show maxmind'
  none    - do not store (you will re-run this wizard to update)""")
    store = click.prompt("Store credentials", type=click.Choice(["config", "command", "none"]),
                         default="config")
    key_cmd = None
    if store == "command":
        key_cmd = click.prompt("Command that prints the license key")

    click.echo(f"\nDownloading {', '.join(editions)} to {dest} ...")
    results = gi.install(editions, creds, dest, force=True, progress=_progress_printer(False))

    values = gi.geo_settings_for(results, dest, editions)
    values["maxmind_account_id"] = creds.account_id if store != "none" else None
    values["maxmind_license_key"] = creds.license_key if store == "config" else None
    values["maxmind_license_key_cmd"] = key_cmd
    path = save_geo_settings(values)
    for r in results:
        click.echo(f"  installed {r.path} (data from {fmt_ts(r.build_epoch)})")
    click.echo(f"Saved GeoIP settings to {path}")

    c.reset_geo()
    resolver = GeoResolver.from_settings(load_geo_settings())
    probe = resolver.lookup("8.8.8.8") if resolver else None
    if probe:
        click.echo(f"Test lookup 8.8.8.8 -> {probe.label or '?'} / {probe.asn_label or '?'}")

    if store != "none":
        line = gi.cron_line()
        click.echo(f"\nMaxMind updates GeoLite2 twice a week. Suggested cron entry:\n  {line}")
        if click.confirm("Add it to your crontab now?", default=False):
            gi.install_cron(line)
            click.echo("Cron job installed.")
    else:
        click.echo("\nCredentials not stored: re-run 'geo setup' to refresh the data.")


@geo.command("update")
@click.option("--force", is_flag=True, help="Download even if the local data is recent.")
@click.option("--quiet", is_flag=True, help="Only print errors (for cron).")
@handle_errors
def geo_update(force, quiet):
    """Refresh GeoLite2 databases using credentials stored by 'geo setup'.

    Skips databases younger than 3 days (MaxMind limits daily downloads) unless --force.
    """
    from pritunl_toolbox import geoinstall as gi

    settings = load_geo_settings()
    creds = gi.load_credentials(settings)
    if creds is None:
        raise click.ClickException("no MaxMind credentials stored; run "
                                   "'pritunl-toolbox geo setup' first")
    editions = [e for e in settings.get("maxmind_editions") or gi.DEFAULT_EDITIONS
                if e in gi.EDITIONS]
    dest = Path(settings.get("dir") or gi.default_install_dir()).expanduser()
    results = gi.install(editions, creds, dest, force=force,
                         progress=_progress_printer(quiet))
    save_geo_settings({k: v for k, v in gi.geo_settings_for(results, dest, editions).items()
                       if v is not None})
    if not quiet:
        for r in results:
            state = "up to date" if r.skipped else "updated"
            click.echo(f"{r.edition}: {state} ({fmt_ts(r.build_epoch)}) {r.path}")


# ----------------------------------------------------------------------------- tui


@cli.command()
@click.option("--refresh", type=click.IntRange(10, 3600), default=30, show_default=True,
              help="Auto-refresh interval in seconds (toggle with 'a' in the UI).")
@pass_ctx
@handle_errors
def tui(c: Ctx, refresh):
    """Interactive terminal UI: dashboard, live sessions, search, whois, servers, report."""
    from pritunl_toolbox.tui import run_tui

    _ = c.profile  # fail early on configuration problems, before the screen switches
    _ = c.geo
    run_tui(c, refresh_seconds=refresh)


def main() -> None:
    cli(prog_name="pritunl-toolbox")

