# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 pritunl-toolbox contributors
"""Offline GeoIP / ASN enrichment from local MaxMind-format (.mmdb) databases.

Privacy by design: lookups never leave this machine. No IP address is sent to any online
geolocation service. Supported databases (any .mmdb with the usual layouts):

  * MaxMind GeoLite2 / GeoIP2 City or Country, and GeoLite2 ASN
    (download and refresh them with MaxMind's official ``geoipupdate`` tool)
  * DB-IP "lite" city/country/asn databases (free, CC BY 4.0)
  * IPinfo "lite" combined country+ASN database

Paths come from env (PRITUNL_GEOIP_CITY / PRITUNL_GEOIP_ASN), the ``[geoip]`` table of the
config file, or well-known locations such as /usr/share/GeoIP and /var/lib/GeoIP.
"""

from __future__ import annotations

import glob
import ipaddress
import os
import threading
from pathlib import Path
from typing import Any

from pritunl_toolbox.models import GeoInfo, User, parse_ip

try:  # pragma: no cover - import guard
    import maxminddb
except ImportError:  # pragma: no cover
    maxminddb = None


class GeoError(Exception):
    pass


SEARCH_DIRS = [
    "/usr/share/GeoIP",
    "/var/lib/GeoIP",
    "/usr/local/share/GeoIP",
    "/usr/local/var/GeoIP",
    "/opt/homebrew/var/GeoIP",
]
CITY_PATTERNS = [
    "GeoIP2-City.mmdb", "GeoLite2-City.mmdb", "dbip-city-lite*.mmdb",
    "GeoIP2-Country.mmdb", "GeoLite2-Country.mmdb", "dbip-country-lite*.mmdb",
    "ipinfo_lite.mmdb",
]
ASN_PATTERNS = ["GeoLite2-ASN.mmdb", "GeoIP2-ISP.mmdb", "dbip-asn-lite*.mmdb", "ipinfo_lite.mmdb"]


def _search_dirs() -> list[Path]:
    data_home = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return [Path(data_home) / "GeoIP", *map(Path, SEARCH_DIRS)]


def _find(patterns: list[str]) -> Path | None:
    for directory in _search_dirs():
        for pattern in patterns:
            # Newest first for date-stamped files such as dbip-city-lite-2026-10.mmdb
            for match in sorted(glob.glob(str(directory / pattern)), reverse=True):
                path = Path(match)
                if path.is_file():
                    return path
    return None


def _validate(path_value: str | os.PathLike | None, what: str) -> Path | None:
    if not path_value:
        return None
    path = Path(path_value).expanduser()
    if not path.is_file():
        raise GeoError(f"GeoIP {what} database not found or not a regular file: {path}")
    return path


def resolve_paths(settings: dict[str, Any] | None = None) -> tuple[Path | None, Path | None]:
    settings = settings or {}
    city = os.environ.get("PRITUNL_GEOIP_CITY") or settings.get("city")
    asn = os.environ.get("PRITUNL_GEOIP_ASN") or settings.get("asn")
    auto_value = os.environ.get("PRITUNL_GEOIP_AUTODISCOVER", settings.get("autodiscover", True))
    auto = str(auto_value).lower() not in ("false", "0", "no", "off")
    city_path = _validate(city, "city") if city else (_find(CITY_PATTERNS) if auto else None)
    asn_path = _validate(asn, "asn") if asn else (_find(ASN_PATTERNS) if auto else None)
    return city_path, asn_path


def _name(record: dict, key: str) -> str | None:
    node = record.get(key)
    if isinstance(node, dict):
        names = node.get("names")
        if isinstance(names, dict):
            return names.get("en") or next(iter(names.values()), None)
    return None


def _str(value: Any, limit: int = 120) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    return str(value)[:limit] or None


def _float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _parse_asn(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).upper().removeprefix("AS")
    return int(text) if text.isdigit() else None


class GeoResolver:
    """Thread-safe, memoising lookups against one or two .mmdb files."""

    def __init__(self, city_reader: Any = None, asn_reader: Any = None,
                 city_path: Path | None = None, asn_path: Path | None = None):
        if city_reader is None and asn_reader is None:
            raise GeoError("no GeoIP database configured or found")
        self._city, self._asn = city_reader, asn_reader
        self.city_path, self.asn_path = city_path, asn_path
        self._cache: dict[str, GeoInfo | None] = {}
        self._lock = threading.Lock()

    @classmethod
    def open(cls, city_path: Path | None, asn_path: Path | None) -> GeoResolver:
        if maxminddb is None:  # pragma: no cover
            raise GeoError("the 'maxminddb' package is not installed")
        try:
            city = maxminddb.open_database(str(city_path)) if city_path else None
            if asn_path and asn_path == city_path:
                asn = city
            else:
                asn = maxminddb.open_database(str(asn_path)) if asn_path else None
        except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
            raise GeoError(f"cannot open GeoIP database: {exc}") from exc
        return cls(city, asn, city_path, asn_path)

    @classmethod
    def from_settings(cls, settings: dict[str, Any] | None = None) -> GeoResolver | None:
        """Resolver from config/env/autodiscovery, or None if no database is available."""
        city, asn = resolve_paths(settings)
        if not city and not asn:
            return None
        return cls.open(city, asn)

    def describe(self) -> list[dict[str, Any]]:
        out = []
        for role, path, reader in (("city", self.city_path, self._city),
                                   ("asn", self.asn_path, self._asn)):
            if reader is None:
                continue
            meta = reader.metadata()
            out.append({
                "role": role, "path": str(path), "type": meta.database_type,
                "build_epoch": meta.build_epoch, "ip_version": meta.ip_version,
            })
        return out

    def lookup(self, value: Any) -> GeoInfo | None:
        ip = parse_ip(value) if not isinstance(value, ipaddress._BaseAddress) else value
        if ip is None:
            return None
        key = str(ip)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        info = self._lookup(ip)
        with self._lock:
            if len(self._cache) > 50_000:
                self._cache.clear()
            self._cache[key] = info
        return info

    def _lookup(self, ip) -> GeoInfo | None:
        if not ip.is_global:
            return GeoInfo(private=True)
        info = GeoInfo()
        found = False
        try:
            rec = self._city.get(str(ip)) if self._city else None
        except ValueError:
            rec = None
        if isinstance(rec, dict):
            found = True
            country = rec.get("country")
            if isinstance(country, dict):
                info.country = _str(country.get("iso_code"), 3)
                info.country_name = _name(rec, "country")
            else:  # IPinfo lite layout
                info.country = _str(rec.get("country_code"), 3)
                info.country_name = _str(country)
            info.city = _name(rec, "city")
            loc = rec.get("location")
            if isinstance(loc, dict):
                info.latitude = _float(loc.get("latitude"))
                info.longitude = _float(loc.get("longitude"))
                info.accuracy_km = _float(loc.get("accuracy_radius"))
        try:
            arec = self._asn.get(str(ip)) if self._asn else None
        except ValueError:
            arec = None
        if isinstance(arec, dict):
            found = True
            info.asn = _parse_asn(arec.get("autonomous_system_number") or arec.get("asn"))
            info.as_org = _str(arec.get("autonomous_system_organization")
                               or arec.get("as_name") or arec.get("isp"))
        return info if found else None

    def close(self) -> None:
        for reader in {id(r): r for r in (self._city, self._asn) if r}.values():
            reader.close()


def enrich_users(users: list[User], resolver: GeoResolver | None) -> None:
    if resolver is None:
        return
    for u in users:
        for e in u.servers:
            if e.connected and e.real_address:
                e.geo = resolver.lookup(e.real_address)

