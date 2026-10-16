# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 pritunl-toolbox contributors
"""Shared runtime context for the CLI and the TUI: profile, API client, GeoIP resolver."""

from __future__ import annotations

from typing import Any

from pritunl_toolbox.api import PritunlClient
from pritunl_toolbox.config import Profile, load_geo_settings, load_profile
from pritunl_toolbox.geo import GeoError, GeoResolver, enrich_users
from pritunl_toolbox.inventory import Inventory, load_inventory
from pritunl_toolbox.output import warn

_UNSET = object()


class Ctx:
    def __init__(self, profile_name: str | None = None, overrides: dict[str, Any] | None = None,
                 geo_mode: bool | None = None):
        """geo_mode: None = use a GeoIP db if one is found, True = require it, False = off."""
        self.profile_name = profile_name
        self.overrides = overrides or {}
        self.geo_mode = geo_mode
        self._profile: Profile | None = None
        self._client: PritunlClient | None = None
        self._geo: Any = _UNSET

    @property
    def profile(self) -> Profile:
        if self._profile is None:
            self._profile = load_profile(self.profile_name, overrides=self.overrides, warn=warn)
            if not self._profile.verify_tls:
                warn("TLS certificate verification is DISABLED; traffic can be intercepted")
        return self._profile

    @property
    def client(self) -> PritunlClient:
        if self._client is None:
            self._client = PritunlClient(self.profile)
        return self._client

    @property
    def geo(self) -> GeoResolver | None:
        if self._geo is _UNSET:
            if self.geo_mode is False:
                self._geo = None
            else:
                try:
                    resolver = GeoResolver.from_settings(load_geo_settings())
                except GeoError as exc:
                    if self.geo_mode:
                        raise
                    warn(f"GeoIP disabled: {exc}")
                    resolver = None
                if resolver is None and self.geo_mode:
                    raise GeoError(
                        "no GeoIP database found; install GeoLite2/DB-IP .mmdb files "
                        "(see 'pritunl-toolbox geo status')")
                self._geo = resolver
        return self._geo

    def reset_geo(self) -> None:
        """Forget the cached resolver (e.g. after databases were installed)."""
        if self._geo not in (_UNSET, None):
            self._geo.close()
        self._geo = _UNSET

    def inventory(self, **kwargs) -> Inventory:
        inv = load_inventory(self.client, **kwargs)
        enrich_users(inv.users, self.geo)
        return inv
