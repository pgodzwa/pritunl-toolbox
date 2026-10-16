# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 pritunl-toolbox contributors
"""Impossible-travel detection.

An *observation* is "user U was seen at IP X (located at lat/lon) at time T". Sources:

  * live sessions: each session yields two observations, at ``connected_since`` and *now*
    (the session is still up). Two concurrent sessions from far-apart places therefore show
    up as travel at infinite speed.
  * Pritunl's per-user audit log (when auditing is enabled on the server): events carry the
    client's remote address and a timestamp, which gives history beyond the current snapshot.

For each user, observations are sorted by time and consecutive pairs are checked. The
distance is reduced by both locations' accuracy radius before dividing by the elapsed time, so
imprecise lookups do not produce false alarms. Pairs closer than ``min_distance_km`` are
ignored entirely, which also covers mobile carriers whose IPs geolocate to a capital city.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from pritunl_toolbox.models import GeoInfo, User

EARTH_RADIUS_KM = 6371.0088
DEFAULT_MAX_SPEED_KMH = 900.0  # roughly airliner cruising speed
DEFAULT_MIN_DISTANCE_KM = 500.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


@dataclass
class Observation:
    user_id: str
    user: str  # "org/name" label
    ts: float
    ip: str
    geo: GeoInfo
    source: str  # "session" | "audit"

    def as_dict(self) -> dict[str, Any]:
        return {"time": self.ts, "ip": self.ip, "location": self.geo.label,
                "asn": self.geo.asn_label, "source": self.source}


@dataclass
class TravelEvent:
    user_id: str
    user: str
    start: Observation
    end: Observation
    distance_km: float
    hours: float
    speed_kmh: float  # math.inf for simultaneous observations
    concurrent: bool = field(default=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id, "user": self.user,
            "from": self.start.as_dict(), "to": self.end.as_dict(),
            "distance_km": round(self.distance_km),
            "hours": round(self.hours, 2),
            "speed_kmh": None if math.isinf(self.speed_kmh) else round(self.speed_kmh),
            "concurrent": self.concurrent,
        }


def effective_distance_km(a: GeoInfo, b: GeoInfo) -> float:
    d = haversine_km(a.latitude, a.longitude, b.latitude, b.longitude)
    return max(0.0, d - (a.accuracy_km or 0.0) - (b.accuracy_km or 0.0))


def session_observations(users: list[User], now: float | None = None) -> list[Observation]:
    now = now or time.time()
    out = []
    for u in users:
        label = f"{u.org_name}/{u.name}"
        for e in u.servers:
            if not (e.connected and e.real_address and e.geo and e.geo.has_location):
                continue
            start = e.connected_since or now
            out.append(Observation(u.id, label, float(start), e.real_address, e.geo, "session"))
            out.append(Observation(u.id, label, now, e.real_address, e.geo, "session"))
    return out


def audit_observations(user: User, audit: list[dict], resolver, since: float = 0.0
                       ) -> list[Observation]:
    label = f"{user.org_name}/{user.name}"
    out = []
    for event in audit:
        if not isinstance(event, dict):
            continue
        addr = event.get("remote_addr") or event.get("remote_address")
        try:
            ts = float(event.get("timestamp") or 0)
        except (TypeError, ValueError):
            continue
        if not addr or ts < since:
            continue
        geo = resolver.lookup(addr)
        if geo and geo.has_location:
            out.append(Observation(user.id, label, ts, str(addr), geo, "audit"))
    return out


def detect(observations: list[Observation], max_speed_kmh: float = DEFAULT_MAX_SPEED_KMH,
           min_distance_km: float = DEFAULT_MIN_DISTANCE_KM) -> list[TravelEvent]:
    by_user: dict[str, list[Observation]] = {}
    for obs in observations:
        by_user.setdefault(obs.user_id, []).append(obs)

    events: list[TravelEvent] = []
    for uid, items in by_user.items():
        items.sort(key=lambda o: (o.ts, o.ip))
        # One event per IP pair: keep the most severe (fastest; concurrent beats everything).
        worst: dict[tuple[str, ...], TravelEvent] = {}
        for a, b in pairwise(items):
            if a.ip == b.ip:
                continue
            dist = effective_distance_km(a.geo, b.geo)
            if dist < min_distance_km:
                continue
            hours = max(0.0, (b.ts - a.ts) / 3600)
            speed = math.inf if hours < 1 / 60 else dist / hours  # < 1 minute apart
            if speed <= max_speed_kmh:
                continue
            pair = tuple(sorted((a.ip, b.ip)))
            if pair not in worst or speed > worst[pair].speed_kmh:
                worst[pair] = TravelEvent(uid, a.user, a, b, dist, hours, speed,
                                          concurrent=math.isinf(speed))
        events.extend(worst.values())
    events.sort(key=lambda e: (-e.speed_kmh if not math.isinf(e.speed_kmh) else -1e18, e.user))
    return events
