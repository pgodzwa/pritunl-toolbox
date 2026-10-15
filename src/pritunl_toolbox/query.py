"""A small query language for searching Pritunl users and sessions.

Syntax: whitespace-separated terms, all of which must match (AND).

    key:value        field match              group:devops   server:prod-*
    -key:value       negation                 -group:contractors
    key:a,b          any of the values (OR)   platform:mac,ios
    value            bare term: IP/CIDR -> ip:, otherwise free text over
                     name, email, id, organization and groups

Value forms for text fields:
    foo     substring (case-insensitive)      ("group" is exact by default)
    =foo    exact (case-insensitive)
    fo*     glob (* ? [..])
    ~re     regular expression (case-insensitive search)

IP fields accept a single address, a CIDR (10.8.0.0/16), a glob (10.8.*) or a prefix (10.8.).

Server-scoped terms (server, vip, rip, ip, platform, device, status:online, connected) must all be
satisfied by the *same* server entry of a user, so ``server:prod vip:10.1.0.5`` means "assigned
10.1.0.5 on prod", not "has prod and has 10.1.0.5 anywhere". Negated server-scoped terms mean
"no entry of this user matches".
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import shlex
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Callable

from pritunl_toolbox.models import ServerEntry, User, parse_ip


class QueryError(ValueError):
    pass


USER_KEYS = {"name", "email", "id", "org", "group", "type", "auth", "text", "inactive",
             "active", "bypass2fa", "pin", "disabled"}
ENTRY_KEYS = {"server", "vip", "rip", "ip", "platform", "device", "connected"}
STATUS_KEY = "status"

ALIASES = {
    "user": "name", "username": "name", "login": "name",
    "mail": "email",
    "organization": "org", "organisation": "org",
    "groups": "group", "grp": "group",
    "auth_type": "auth",
    "vpn": "vip", "vpn_ip": "vip", "vpnip": "vip", "virt": "vip", "virt_ip": "vip",
    "real": "rip", "real_ip": "rip", "realip": "rip", "src": "rip", "public": "rip",
    "os": "platform",
    "srv": "server",
    "state": "status",
    "bypass_secondary": "bypass2fa", "no2fa": "bypass2fa",
}

ALL_KEYS = USER_KEYS | ENTRY_KEYS | {STATUS_KEY}

_GLOB_CHARS = set("*?[")
_DURATION = re.compile(r"^(\d+)\s*([smhdw]?)$")
_UNITS = {"": 86400, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_TRUE = {"yes", "y", "true", "1", "on"}
_FALSE = {"no", "n", "false", "0", "off"}


def parse_duration(text: str) -> int:
    m = _DURATION.match(text.strip().lower())
    if not m:
        raise QueryError(f"invalid duration '{text}' (examples: 30d, 12h, 2w)")
    return int(m.group(1)) * _UNITS[m.group(2)]


def _parse_bool(key: str, text: str) -> bool:
    t = text.strip().lower()
    if t in _TRUE:
        return True
    if t in _FALSE:
        return False
    raise QueryError(f"{key}: expected yes/no, got '{text}'")


def text_matcher(value: str, default: str = "substring") -> Callable[[str | None], bool]:
    if value.startswith("~"):
        try:
            rx = re.compile(value[1:], re.IGNORECASE)
        except re.error as exc:
            raise QueryError(f"invalid regex '{value[1:]}': {exc}") from exc
        return lambda s: bool(s) and rx.search(s) is not None
    if value.startswith("="):
        target = value[1:].casefold()
        return lambda s: (s or "").casefold() == target
    needle = value.casefold()
    if _GLOB_CHARS & set(value):
        return lambda s: fnmatch.fnmatchcase((s or "").casefold(), needle)
    if default == "exact":
        return lambda s: (s or "").casefold() == needle
    return lambda s: bool(s) and needle in s.casefold()


def ip_matcher(value: str) -> Callable[[ipaddress._BaseAddress | None], bool]:
    value = value.strip()
    if not value:
        raise QueryError("empty IP value")
    try:
        net = ipaddress.ip_network(value, strict=False)
        return lambda ip: ip is not None and ip.version == net.version and ip in net
    except ValueError:
        pass
    single = parse_ip(value)
    if single is not None:
        return lambda ip: ip == single
    if _GLOB_CHARS & set(value):
        return lambda ip: ip is not None and fnmatch.fnmatchcase(str(ip), value.lower())
    if not re.fullmatch(r"[0-9a-fA-F:.]+", value):
        raise QueryError(f"'{value}' is not an IP, CIDR, glob or prefix")
    return lambda ip: ip is not None and str(ip).startswith(value.lower())


def looks_like_ip(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return parse_ip(token) is not None


@dataclass
class Term:
    key: str
    raw: str
    negate: bool
    scope: str  # "user" | "entry"
    user_pred: Callable[[User], bool] | None = None
    entry_pred: Callable[[ServerEntry], bool] | None = None

    def __str__(self) -> str:
        return f"{'-' if self.negate else ''}{self.key}:{self.raw}"


def _any_of(values: list[str], build):
    preds = [build(v) for v in values]
    return lambda obj: any(p(obj) for p in preds)


def _build_term(key: str, raw: str, negate: bool, now: float) -> Term:
    key = ALIASES.get(key.lower(), key.lower())
    if key not in ALL_KEYS:
        raise QueryError(f"unknown search key '{key}'. Known keys: {', '.join(sorted(ALL_KEYS))}")
    values = [v for v in raw.split(",") if v != ""] if not raw.startswith("~") else [raw]
    if not values:
        raise QueryError(f"{key}: empty value")

    def user_term(pred):
        return Term(key, raw, negate, "user", user_pred=pred)

    def entry_term(pred):
        # Negated entry terms become user-level "no entry matches".
        if negate:
            return Term(key, raw, negate, "user",
                        user_pred=lambda u: any(pred(e) for e in u.servers))
        return Term(key, raw, negate, "entry", entry_pred=pred)

    if key == "status":
        preds_u, preds_e = [], []
        for v in values:
            v = v.lower()
            if v == "online":
                preds_e.append(lambda e: e.connected)
            elif v == "offline":
                preds_u.append(lambda u: not u.online)
            elif v == "disabled":
                preds_u.append(lambda u: u.disabled)
            elif v in ("enabled", "active"):
                preds_u.append(lambda u: not u.disabled)
            else:
                raise QueryError(f"status: expected online/offline/disabled/enabled, got '{v}'")
        if preds_e and not preds_u:
            return entry_term(lambda e: any(p(e) for p in preds_e))
        # Mixed: evaluate everything at user level.
        return user_term(lambda u: any(p(u) for p in preds_u)
                         or any(p(e) for p in preds_e for e in u.servers))

    if key == "connected":
        want = _parse_bool(key, values[0])
        return entry_term(lambda e: e.connected == want)
    if key == "disabled":
        want = _parse_bool(key, values[0])
        return user_term(lambda u: u.disabled == want)
    if key == "bypass2fa":
        want = _parse_bool(key, values[0])
        return user_term(lambda u: u.bypass_secondary == want)
    if key == "pin":
        want = _parse_bool(key, values[0])
        return user_term(lambda u: u.pin == want)
    if key in ("inactive", "active"):
        cutoff = now - parse_duration(values[0])
        if key == "inactive":
            return user_term(lambda u: not u.last_active or u.last_active < cutoff)
        return user_term(lambda u: bool(u.last_active) and u.last_active >= cutoff)

    if key in ("name", "email", "org", "type", "auth"):
        attr = {"name": "name", "email": "email", "org": "org_name",
                "type": "type", "auth": "auth_type"}[key]
        default = "exact" if key in ("type", "auth") else "substring"
        m = _any_of(values, lambda v: text_matcher(v, default))
        if key == "org":
            return user_term(lambda u: m(u.org_name) or u.org_id == raw)
        return user_term(lambda u: m(getattr(u, attr)))
    if key == "id":
        m = _any_of(values, lambda v: text_matcher(v, "exact") if _GLOB_CHARS & set(v)
                    else (lambda s, v=v: (s or "").lower().startswith(v.lower())))
        return user_term(lambda u: m(u.id))
    if key == "group":
        m = _any_of(values, lambda v: text_matcher(v, "exact"))
        return user_term(lambda u: any(m(g) for g in u.groups))
    if key == "text":
        m = text_matcher(raw)
        return user_term(lambda u: m(u.name) or m(u.email) or m(u.org_name)
                         or u.id == raw or any(m(g) for g in u.groups))

    if key == "server":
        m = _any_of(values, lambda v: text_matcher(v, "substring"))
        return entry_term(lambda e: m(e.server_name) or e.server_id == raw)
    if key in ("platform", "device"):
        attr = "platform" if key == "platform" else "device_name"
        m = _any_of(values, lambda v: text_matcher(v, "substring"))
        return entry_term(lambda e: e.connected and m(getattr(e, attr)))
    if key in ("vip", "rip", "ip"):
        m = _any_of(values, ip_matcher)
        if key == "vip":
            return entry_term(lambda e: any(m(ip) for ip in e.vpn_ips))
        if key == "rip":
            return entry_term(lambda e: m(e.real_ip))
        return entry_term(lambda e: m(e.real_ip) or any(m(ip) for ip in e.vpn_ips))

    raise QueryError(f"unhandled key '{key}'")  # pragma: no cover


def tokenize(parts: Iterable[str]) -> list[str]:
    tokens: list[str] = []
    for part in parts:
        try:
            tokens.extend(shlex.split(part))
        except ValueError as exc:
            raise QueryError(f"cannot parse '{part}': {exc}") from exc
    return tokens


def parse_query(parts: Iterable[str], now: float | None = None) -> list[Term]:
    now = time.time() if now is None else now
    terms: list[Term] = []
    for token in tokenize(parts):
        negate = False
        if token[:1] in ("-", "!") and len(token) > 1:
            negate, token = True, token[1:]
        # IPv6 addresses contain ':', so check for a bare IP/CIDR before splitting key:value.
        if looks_like_ip(token):
            key, value = "ip", token
        else:
            key, sep, value = token.partition(":")
            if not sep:
                key, value = "text", token
        terms.append(_build_term(key, value, negate, now))
    return terms


@dataclass
class Match:
    user: User
    entries: list[ServerEntry]  # entries satisfying positive server-scoped terms


class Query:
    def __init__(self, terms: list[Term]):
        self.terms = terms
        self.user_terms = [t for t in terms if t.scope == "user"]
        self.entry_terms = [t for t in terms if t.scope == "entry"]

    @classmethod
    def parse(cls, parts: Iterable[str], now: float | None = None) -> Query:
        return cls(parse_query(parts, now))

    @property
    def has_entry_terms(self) -> bool:
        return bool(self.entry_terms)

    def match(self, user: User) -> Match | None:
        for t in self.user_terms:
            ok = t.user_pred(user)
            if ok == t.negate:
                return None
        if self.entry_terms:
            entries = [e for e in user.servers if all(t.entry_pred(e) for t in self.entry_terms)]
            if not entries:
                return None
        else:
            # Nothing server-specific asked: show live sessions, or assignments if offline.
            entries = user.sessions or list(user.servers)
        return Match(user, entries)

    def run(self, users: Iterable[User]) -> list[Match]:
        out = []
        for u in users:
            m = self.match(u)
            if m is not None:
                out.append(m)
        return out

    def __str__(self) -> str:
        return " ".join(str(t) for t in self.terms) or "(all)"
