# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 pritunl-toolbox contributors
"""Fetches a consistent snapshot of organizations, users and servers."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from pritunl_toolbox.api import PritunlClient
from pritunl_toolbox.models import Organization, Server, User


@dataclass
class Inventory:
    orgs: list[Organization] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
    servers: list[Server] = field(default_factory=list)
    fetched_at: float = field(default_factory=time.time)

    def server_by_ref(self, ref: str) -> list[Server]:
        """Find servers by exact id, exact name (case-insensitive) or unique prefix."""
        ref_l = ref.lower()
        exact = [s for s in self.servers if s.id == ref or s.name.lower() == ref_l]
        if exact:
            return exact
        return [s for s in self.servers if s.name.lower().startswith(ref_l)]

    def org_by_ref(self, ref: str) -> list[Organization]:
        ref_l = ref.lower()
        exact = [o for o in self.orgs if o.id == ref or o.name.lower() == ref_l]
        if exact:
            return exact
        return [o for o in self.orgs if o.name.lower().startswith(ref_l)]

    def find_users(self, ident: str, org: str | None = None) -> list[User]:
        """Resolve a user by id, exact name or exact email (case-insensitive)."""
        ident_l = ident.lower()
        pool = self.users
        if org:
            org_ids = {o.id for o in self.org_by_ref(org)}
            pool = [u for u in pool if u.org_id in org_ids]
        by_id = [u for u in pool if u.id == ident]
        if by_id:
            return by_id
        return [u for u in pool
                if u.name.lower() == ident_l or (u.email or "").lower() == ident_l]


def normalize_server_ids(users: list[User], servers: list[Server]) -> None:
    """Point every server entry at the real server id.

    Connected entries arrive with the client *session* id in ``id``/``server_id`` (see
    ServerEntry), so they are resolved by server name. Names are unique in practice; if two
    servers ever share a name the entry is left untouched rather than guessed.
    """
    known = {s.id for s in servers}
    by_name: dict[str, list[str]] = {}
    for s in servers:
        by_name.setdefault(s.name, []).append(s.id)
    for u in users:
        for e in u.servers:
            if e.server_id in known:
                continue
            ids = by_name.get(e.server_name, [])
            if len(ids) == 1:
                e.server_id = ids[0]


def load_inventory(client: PritunlClient, *, with_users: bool = True,
                   org_filter: str | None = None, workers: int | None = None) -> Inventory:
    workers = workers or client.profile.workers
    inv = Inventory()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # The server list is always needed: it maps live sessions back to their server.
        servers_f = pool.submit(client.servers)
        inv.orgs = [Organization.from_api(o) for o in client.organizations()]
        if org_filter:
            inv.orgs = inv.org_by_ref(org_filter)
        if with_users:
            futures = [(org, pool.submit(client.users, org.id)) for org in inv.orgs]
            for org, fut in futures:
                inv.users.extend(User.from_api(u, org) for u in fut.result()
                                 if isinstance(u, dict))
        inv.servers = [Server.from_api(s) for s in servers_f.result()]
    normalize_server_ids(inv.users, inv.servers)
    inv.fetched_at = time.time()
    return inv
