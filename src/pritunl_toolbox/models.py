"""Typed views over Pritunl API payloads.

Only an explicit allowlist of fields is copied from API responses. Sensitive values that the
API returns (user ``otp_secret``, organization ``auth_token``/``auth_secret``, ...) are never
stored, so they cannot end up in tables, JSON or CSV exports by accident.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_BRACKETED = re.compile(r"^\[([0-9a-fA-F:.]+)\](?::\d+)?$")
_V4_PORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$")


def parse_ip(value: Any) -> IPAddress | None:
    """Parse '1.2.3.4', '1.2.3.4:1194', '10.0.0.2/24', '[fd00::1]:443', 'fd00::2/64'."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    m = _BRACKETED.match(text) or _V4_PORT.match(text)
    if m:
        text = m.group(1)
    text = text.split("%", 1)[0]  # drop IPv6 zone id
    try:
        return ipaddress.ip_interface(text).ip
    except ValueError:
        return None


def ip_str(value: Any) -> str | None:
    ip = parse_ip(value)
    return str(ip) if ip else (str(value) if value else None)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "", 0) else None
    except (TypeError, ValueError):
        return None


@dataclass
class Organization:
    id: str
    name: str
    user_count: int | None = None

    @classmethod
    def from_api(cls, d: dict) -> Organization:
        return cls(id=str(d.get("id", "")), name=str(d.get("name") or ""),
                   user_count=_int_or_none(d.get("user_count")))


@dataclass
class Server:
    id: str
    name: str
    status: str = "unknown"
    uptime: int | None = None
    users_online: int = 0
    devices_online: int = 0
    user_count: int = 0
    network: str | None = None
    network6: str | None = None
    port: int | None = None
    protocol: str | None = None
    groups: list[str] = field(default_factory=list)
    wg: bool = False
    network_wg: str | None = None
    port_wg: int | None = None
    otp_auth: bool = False
    sso_auth: bool = False

    @classmethod
    def from_api(cls, d: dict) -> Server:
        return cls(
            id=str(d.get("id", "")),
            name=str(d.get("name") or ""),
            status=str(d.get("status") or "unknown"),
            uptime=_int_or_none(d.get("uptime")),
            users_online=int(d.get("users_online") or 0),
            devices_online=int(d.get("devices_online") or 0),
            user_count=int(d.get("user_count") or 0),
            network=d.get("network"),
            network6=d.get("network6") if d.get("ipv6") else None,
            port=_int_or_none(d.get("port")),
            protocol=d.get("protocol"),
            groups=list(d.get("groups") or []),
            wg=bool(d.get("wg")),
            network_wg=d.get("network_wg") if d.get("wg") else None,
            port_wg=_int_or_none(d.get("port_wg")) if d.get("wg") else None,
            otp_auth=bool(d.get("otp_auth")),
            sso_auth=bool(d.get("sso_auth")),
        )


@dataclass
class Host:
    id: str
    name: str
    hostname: str | None = None
    status: str = "unknown"
    uptime: int | None = None
    public_addr: str | None = None
    public_addr6: str | None = None
    local_addr: str | None = None
    version: str | None = None

    @classmethod
    def from_api(cls, d: dict) -> Host:
        return cls(
            id=str(d.get("id", "")),
            name=str(d.get("name") or ""),
            hostname=d.get("hostname"),
            status=str(d.get("status") or "unknown"),
            uptime=_int_or_none(d.get("uptime")),
            public_addr=d.get("public_addr"),
            public_addr6=d.get("public_addr6"),
            local_addr=d.get("local_addr"),
            version=d.get("version"),
        )


@dataclass
class GeoInfo:
    """Offline GeoIP/ASN data for one address (filled in from local .mmdb files)."""

    country: str | None = None  # ISO 3166-1 alpha-2
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    accuracy_km: float | None = None
    asn: int | None = None
    as_org: str | None = None
    private: bool = False

    @property
    def has_location(self) -> bool:
        return self.latitude is not None and self.longitude is not None

    @property
    def label(self) -> str:
        if self.private:
            return "private"
        return " ".join(p for p in (self.country, self.city) if p)

    @property
    def asn_label(self) -> str:
        if self.asn is None:
            return self.as_org or ""
        return f"AS{self.asn} {self.as_org or ''}".strip()


@dataclass
class ServerEntry:
    """A user's relation to one server: assigned VPN IP and, if online, the live session.

    Pritunl quirk: for a *connected* entry the API replaces both ``id`` and ``server_id`` with
    the client session id (pritunl/handlers/user.py, user_get). The session id is kept in
    ``session_id`` and ``server_id`` is mapped back to the real server by name in
    :func:`pritunl_toolbox.inventory.load_inventory`.
    """

    server_id: str
    server_name: str
    connected: bool = False
    virt_address: str | None = None
    virt_address6: str | None = None
    real_address: str | None = None
    connected_since: int | None = None
    device_name: str | None = None
    platform: str | None = None
    geo: GeoInfo | None = None  # location of real_address, when a GeoIP db is configured
    session_id: str | None = None  # Pritunl client session id for connected entries

    @classmethod
    def from_api(cls, d: dict) -> ServerEntry:
        connected = bool(d.get("status"))
        raw_id = str(d.get("server_id") or d.get("id") or "")
        return cls(
            server_id=raw_id,
            session_id=str(d.get("id") or raw_id) if connected else None,
            server_name=str(d.get("name") or ""),
            connected=connected,
            virt_address=ip_str(d.get("virt_address")),
            virt_address6=ip_str(d.get("virt_address6")),
            real_address=ip_str(d.get("real_address")),
            connected_since=_int_or_none(d.get("connected_since")),
            device_name=d.get("device_name"),
            platform=d.get("platform"),
        )

    @property
    def vpn_ips(self) -> list[IPAddress]:
        return [ip for ip in (parse_ip(self.virt_address), parse_ip(self.virt_address6)) if ip]

    @property
    def real_ip(self) -> IPAddress | None:
        return parse_ip(self.real_address) if self.connected else None


@dataclass
class User:
    id: str
    name: str
    org_id: str
    org_name: str
    email: str | None = None
    groups: list[str] = field(default_factory=list)
    type: str | None = None
    auth_type: str | None = None
    disabled: bool = False
    bypass_secondary: bool = False
    pin: bool = False
    last_active: int | None = None
    servers: list[ServerEntry] = field(default_factory=list)

    @classmethod
    def from_api(cls, d: dict, org: Organization | None = None) -> User:
        return cls(
            id=str(d.get("id", "")),
            name=str(d.get("name") or ""),
            org_id=str(d.get("organization") or (org.id if org else "")),
            org_name=str(d.get("organization_name") or (org.name if org else "")),
            email=d.get("email") or None,
            groups=[str(g) for g in (d.get("groups") or [])],
            type=d.get("type"),
            auth_type=d.get("auth_type"),
            disabled=bool(d.get("disabled")),
            bypass_secondary=bool(d.get("bypass_secondary")),
            pin=bool(d.get("pin")),
            last_active=_int_or_none(d.get("last_active")),
            servers=[ServerEntry.from_api(s) for s in (d.get("servers") or [])
                     if isinstance(s, dict)],
        )

    @property
    def online(self) -> bool:
        return any(s.connected for s in self.servers)

    @property
    def sessions(self) -> list[ServerEntry]:
        return [s for s in self.servers if s.connected]

    @property
    def state(self) -> str:
        if self.disabled:
            return "disabled-online" if self.online else "disabled"
        return "online" if self.online else "offline"


def to_dict(obj: Any) -> Any:
    return asdict(obj)
