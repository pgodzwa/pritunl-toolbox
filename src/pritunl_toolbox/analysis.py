"""Row builders for the CLI and the security/health findings used by ``report``."""

from __future__ import annotations

import re
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Any

from pritunl_toolbox.inventory import Inventory
from pritunl_toolbox.models import ServerEntry, User
from pritunl_toolbox.output import fmt_ago, fmt_duration, iso_ts
from pritunl_toolbox.query import Match

# ----------------------------------------------------------------------------- rows

USER_COLUMNS = [
    ("org", "Org"), ("user", "User"), ("email", "Email"), ("groups", "Groups"),
    ("state", "State"), ("servers", "Server"), ("vpn_ip", "VPN IP"),
    ("real_ip", "Real IP"), ("last_active", "Last active"),
]

SESSION_COLUMNS = [
    ("org", "Org"), ("user", "User"), ("groups", "Groups"), ("server", "Server"),
    ("state", "State"), ("vpn_ip", "VPN IP"), ("real_ip", "Real IP"),
    ("uptime", "Connected"), ("device", "Device"), ("platform", "Platform"),
]

GEO_COLUMNS = [("location", "Location"), ("asn", "ASN")]


def with_geo(columns: list[tuple[str, str]], geo: bool, after: str = "real_ip"
             ) -> list[tuple[str, str]]:
    """Insert the Location/ASN columns right after ``after`` when geo data is available."""
    if not geo:
        return list(columns)
    out: list[tuple[str, str]] = []
    for col in columns:
        out.append(col)
        if col[0] == after:
            out.extend(GEO_COLUMNS)
    return out


def geo_label(entry: ServerEntry) -> str:
    return entry.geo.label if entry.connected and entry.geo else ""


def asn_label(entry: ServerEntry) -> str:
    return entry.geo.asn_label if entry.connected and entry.geo else ""


def entry_state(user: User, entry: ServerEntry) -> str:
    if entry.connected:
        return "disabled-online" if user.disabled else "online"
    return "disabled" if user.disabled else "offline"


def session_row(user: User, entry: ServerEntry, now: float | None = None) -> dict[str, Any]:
    now = now or time.time()
    return {
        "org": user.org_name,
        "user": user.name,
        "email": user.email,
        "groups": user.groups,
        "server": entry.server_name,
        "state": entry_state(user, entry),
        "vpn_ip": [entry.virt_address, entry.virt_address6],
        "real_ip": entry.real_address if entry.connected else None,
        "uptime": fmt_duration(now - entry.connected_since)
        if entry.connected and entry.connected_since else "",
        "device": entry.device_name if entry.connected else None,
        "platform": entry.platform if entry.connected else None,
        "location": geo_label(entry),
        "asn": asn_label(entry),
    }


def user_row(match: Match, now: float | None = None) -> dict[str, Any]:
    u, entries = match.user, match.entries
    # Server / VPN IP / Real IP are parallel lists, one line per entry, so cells stay aligned.
    any_live = any(e.connected for e in entries)
    return {
        "org": u.org_name,
        "user": u.name,
        "email": u.email,
        "groups": u.groups,
        "state": u.state,
        "servers": [e.server_name for e in entries],
        "vpn_ip": [" ".join(ip for ip in (e.virt_address, e.virt_address6) if ip) or "-"
                   for e in entries],
        "real_ip": [(e.real_address or "?") if e.connected else "-" for e in entries]
        if any_live else [],
        "location": [geo_label(e) or "-" for e in entries] if any_live else [],
        "asn": [asn_label(e) or "-" for e in entries] if any_live else [],
        "last_active": fmt_ago(u.last_active, now),
    }


def entry_json(entry: ServerEntry) -> dict[str, Any]:
    d = asdict(entry)
    d["connected_since_iso"] = iso_ts(entry.connected_since)
    return d


def user_json(user: User, entries: list[ServerEntry] | None = None) -> dict[str, Any]:
    d = asdict(user)
    d.pop("servers")
    d["state"] = user.state
    d["last_active_iso"] = iso_ts(user.last_active)
    d["servers"] = [entry_json(e) for e in (user.servers if entries is None else entries)]
    return d


def session_json(user: User, entry: ServerEntry) -> dict[str, Any]:
    return {
        "user_id": user.id, "user": user.name, "email": user.email,
        "org_id": user.org_id, "org": user.org_name, "groups": user.groups,
        "disabled": user.disabled, **entry_json(entry),
    }


def iter_sessions(users: list[User]):
    for u in users:
        for e in u.servers:
            if e.connected:
                yield u, e


_HOST_BAD = re.compile(r"[^a-z0-9-]+")


def hostname_label(value: str) -> str:
    label = _HOST_BAD.sub("-", value.lower()).strip("-")
    return label[:63] or "unnamed"


# ----------------------------------------------------------------------------- report


@dataclass
class Finding:
    severity: str  # high | medium | low | info
    check: str
    subject: str
    detail: str


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def build_report(inv: Inventory, inactive_days: int = 90, shared_ip_threshold: int = 5,
                 now: float | None = None, allowed_countries: set[str] | None = None,
                 travel_events: list | None = None) -> dict[str, Any]:
    now = now or time.time()
    users = inv.users
    sessions = list(iter_sessions(users))
    findings: list[Finding] = []

    # Geo-based checks (only when a GeoIP database enriched the sessions).
    if allowed_countries:
        allowed = {c.upper() for c in allowed_countries}
        for u, e in sessions:
            if e.geo is None or e.geo.private:
                continue
            if (e.geo.country or "??") not in allowed:
                findings.append(Finding(
                    "medium", "unexpected-country", f"{u.org_name}/{u.name}",
                    f"session on {e.server_name} from {e.real_address} "
                    f"({e.geo.label or 'unknown location'}, {e.geo.asn_label or 'unknown ASN'})"))
    for ev in travel_events or []:
        speed = "simultaneously" if ev.concurrent else f"at {ev.speed_kmh:,.0f} km/h"
        findings.append(Finding(
            "medium", "impossible-travel", ev.user,
            f"{ev.start.ip} ({ev.start.geo.label}) -> {ev.end.ip} ({ev.end.geo.label}): "
            f"{ev.distance_km:,.0f} km {speed}"))

    # Disabled users that still hold a live session.
    for u, e in sessions:
        if u.disabled:
            findings.append(Finding(
                "high", "disabled-user-connected", f"{u.org_name}/{u.name}",
                f"connected to {e.server_name} from {e.real_address} ({e.virt_address})"))

    # One account used from several public IPs at the same time -> possible credential sharing.
    by_user: dict[str, set[str]] = defaultdict(set)
    user_index = {u.id: u for u in users}
    for u, e in sessions:
        if e.real_address:
            by_user[u.id].add(e.real_address)
    for uid, ips in by_user.items():
        if len(ips) > 1:
            u = user_index[uid]
            findings.append(Finding(
                "medium", "multiple-source-ips", f"{u.org_name}/{u.name}",
                f"concurrent sessions from {len(ips)} real IPs: {', '.join(sorted(ips))}"))

    # The same VPN address assigned to two users on one server -> routing conflict.
    by_vip: dict[tuple[str, str], list[User]] = defaultdict(list)
    for u in users:
        for e in u.servers:
            for ip in e.vpn_ips:
                by_vip[(e.server_name, str(ip))].append(u)
    for (server, ip), owners in by_vip.items():
        if len({o.id for o in owners}) > 1:
            findings.append(Finding(
                "high", "duplicate-vpn-ip", f"{server} {ip}",
                "assigned to " + ", ".join(f"{o.org_name}/{o.name}" for o in owners)))

    # Many different users behind one public IP: usually an office NAT, worth knowing.
    by_rip: dict[str, set[str]] = defaultdict(set)
    for u, e in sessions:
        if e.real_address:
            by_rip[e.real_address].add(u.name)
    for rip, names in by_rip.items():
        if len(names) >= shared_ip_threshold:
            findings.append(Finding("info", "shared-source-ip", rip,
                                    f"{len(names)} users connect from this IP"))

    for u in users:
        if u.bypass_secondary and not u.disabled:
            findings.append(Finding("medium", "bypass-2fa", f"{u.org_name}/{u.name}",
                                    "user bypasses secondary authentication"))

    cutoff = now - inactive_days * 86400
    for u in users:
        if u.disabled or u.type not in (None, "client"):
            continue
        if not u.last_active:
            findings.append(Finding("low", "never-active", f"{u.org_name}/{u.name}",
                                    "enabled account that never connected"))
        elif u.last_active < cutoff:
            findings.append(Finding(
                "low", "inactive-user", f"{u.org_name}/{u.name}",
                f"enabled but last active {fmt_ago(u.last_active, now)}; consider disabling"))

    for s in inv.servers:
        if not s.otp_auth and not s.sso_auth:
            findings.append(Finding("info", "server-without-2fa", s.name,
                                    "neither OTP nor SSO authentication enabled on server"))
        if s.status != "online":
            findings.append(Finding("info", "server-not-online", s.name, f"status: {s.status}"))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.check, f.subject))

    per_server: dict[str, dict[str, Any]] = {}
    for s in inv.servers:
        per_server[s.name] = {"server": s.name, "status": s.status, "sessions": 0,
                              "users": set(), "platforms": Counter()}
    for u, e in sessions:
        row = per_server.setdefault(e.server_name, {"server": e.server_name, "status": "?",
                                                    "sessions": 0, "users": set(),
                                                    "platforms": Counter()})
        row["sessions"] += 1
        row["users"].add(u.id)
        row["platforms"][e.platform or "unknown"] += 1
    server_rows = [
        {"server": r["server"], "status": r["status"], "sessions": r["sessions"],
         "users": len(r["users"]),
         "platforms": [f"{p}: {n}" for p, n in r["platforms"].most_common()]}
        for r in sorted(per_server.values(), key=lambda r: (-r["sessions"], r["server"]))
    ]

    group_total: Counter = Counter()
    group_online: Counter = Counter()
    for u in users:
        for g in u.groups or ["(none)"]:
            group_total[g] += 1
            if u.online:
                group_online[g] += 1
    group_rows = [{"group": g, "users": n, "online": group_online[g]}
                  for g, n in group_total.most_common()]

    countries = Counter((e.geo.country or ("private" if e.geo.private else "unknown"))
                        for _, e in sessions if e.geo is not None)
    country_rows = [{"country": c, "sessions": n} for c, n in countries.most_common()]

    platforms = Counter((e.platform or "unknown") for _, e in sessions)
    overview = {
        "organizations": len(inv.orgs),
        "users": len(users),
        "disabled_users": sum(1 for u in users if u.disabled),
        "online_users": sum(1 for u in users if u.online),
        "sessions": len(sessions),
        "servers": len(inv.servers),
        "servers_online": sum(1 for s in inv.servers if s.status == "online"),
        "platforms": dict(platforms.most_common()),
        "generated_at": iso_ts(now),
    }
    return {
        "overview": overview,
        "servers": server_rows,
        "groups": group_rows,
        "countries": country_rows,
        "findings": [asdict(f) for f in findings],
    }

