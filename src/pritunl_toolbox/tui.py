"""Interactive terminal UI (Textual).

Security notes:
  * Every cell/label is a pre-sanitised ``rich.text.Text``. Textual's DataTable parses plain
    strings as markup, and values like device names come from VPN clients, so plain strings
    are never handed to widgets.
  * Notifications are sent with ``markup=False``.
  * Write actions (enable/disable) are only offered on read-write profiles and always ask
    for confirmation.
  * Exports go to ~/pritunl-toolbox-exports (mode 700), files created exclusively with mode 600.
"""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)

from pritunl_toolbox.analysis import (
    SESSION_COLUMNS,
    SEVERITY_ORDER,
    USER_COLUMNS,
    build_report,
    iter_sessions,
    session_row,
    user_row,
    with_geo,
)
from pritunl_toolbox.api import PritunlAPIError
from pritunl_toolbox.config import ConfigError
from pritunl_toolbox.context import Ctx
from pritunl_toolbox.geo import GeoError
from pritunl_toolbox.inventory import Inventory
from pritunl_toolbox.models import Server, User
from pritunl_toolbox.output import (
    STYLE_BY_VALUE,
    fmt_ago,
    fmt_duration,
    fmt_ts,
    render_csv,
    sanitize,
)
from pritunl_toolbox.query import Match, Query, QueryError
from pritunl_toolbox.travel import detect, session_observations

Column = tuple[str, str]
EXPECTED_ERRORS = (PritunlAPIError, ConfigError, GeoError, QueryError)

SEVERITY_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}


def txt(value: Any, style: str = "") -> Text:
    """Untrusted value -> safe Text (no markup, no control characters)."""
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(sanitize(v) for v in value if v not in (None, ""))
    elif isinstance(value, bool):
        value = "yes" if value else "no"
    text = sanitize(value)
    return Text(text, style=style or STYLE_BY_VALUE.get(text, "") or SEVERITY_STYLE.get(text, ""))


def fill_table(table: DataTable, columns: Sequence[Column], rows: Sequence[dict]) -> None:
    """Replace the table contents and keep the cursor where it was if possible."""
    cursor = table.cursor_row
    table.clear(columns=True)
    for key, header in columns:
        table.add_column(header, key=key)
    for i, row in enumerate(rows):
        table.add_row(*(txt(row.get(key)) for key, _ in columns), key=str(i))
    if rows:
        table.move_cursor(row=min(cursor, len(rows) - 1), animate=False)


def export_dir() -> Path:
    path = Path.home() / "pritunl-toolbox-exports"
    if path.is_symlink():
        raise OSError(f"{path} is a symlink; refusing to write exports through it")
    path.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)  # tighten a pre-existing directory too
    return path


def write_export(name: str, columns: Sequence[Column], rows: Sequence[dict]) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = export_dir() / f"{name}-{stamp}.csv"
    # O_EXCL: never follow a pre-planted symlink or overwrite an existing file.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        render_csv(rows, columns, fh)
    return path


# ----------------------------------------------------------------------------- modals


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel")]

    def __init__(self, question: str):
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm"):
            yield Static(txt(self.question, "bold"))
            with Horizontal(classes="buttons"):
                yield Button("Yes", id="yes", variant="error")
                yield Button("No", id="no", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    @on(Button.Pressed)
    def answer(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class UserScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss", "Close"), Binding("q", "dismiss", "Close")]

    def __init__(self, ctx: Ctx, user: User):
        super().__init__()
        self.ctx = ctx
        self.user = user

    def compose(self) -> ComposeResult:
        u = self.user
        read_only = self.ctx.profile.read_only
        with Vertical(id="dialog"):
            yield Static(self._info(), id="user-info")
            yield Label(Text("Servers", style="bold"))
            yield DataTable(id="user-servers", cursor_type="row", zebra_stripes=True)
            yield Label(Text("Audit log", style="bold"))
            yield DataTable(id="user-audit", cursor_type="row", zebra_stripes=True)
            with Horizontal(classes="buttons"):
                yield Button("Load audit log", id="btn-audit")
                toggle = Button("Enable user" if u.disabled else "Disable user",
                                id="btn-toggle", variant="success" if u.disabled else "error",
                                disabled=read_only)
                if read_only:
                    toggle.tooltip = "Profile is read-only"
                yield toggle
                yield Button("Close", id="btn-close", variant="primary")

    def _info(self) -> Text:
        u = self.user
        out = Text()
        out.append(sanitize(u.name), style="bold")
        out.append(f"  <{sanitize(u.email or '')}>  ")
        out.append(sanitize(u.state), style=STYLE_BY_VALUE.get(u.state, ""))
        out.append(f"\nOrg: {sanitize(u.org_name)}   Groups: "
                   f"{sanitize(', '.join(u.groups) or '-')}   ID: {sanitize(u.id)}")
        out.append(f"\nAuth: {sanitize(u.auth_type or '-')}   Type: {sanitize(u.type or '-')}"
                   f"   PIN: {'yes' if u.pin else 'no'}   Last active: "
                   f"{fmt_ts(u.last_active) or 'never'} ({fmt_ago(u.last_active)})")
        if u.bypass_secondary:
            out.append("\nThis user bypasses secondary (2FA) authentication", style="yellow")
        return out

    def on_mount(self) -> None:
        cols = with_geo([c for c in SESSION_COLUMNS if c[0] not in ("org", "user", "groups")],
                        self.ctx.geo is not None)
        now = time.time()
        fill_table(self.query_one("#user-servers", DataTable), cols,
                   [session_row(self.user, e, now) for e in self.user.servers])

    @on(Button.Pressed, "#btn-close")
    def close(self) -> None:
        self.dismiss()

    @on(Button.Pressed, "#btn-audit")
    def load_audit(self) -> None:
        self.query_one("#btn-audit", Button).disabled = True
        self._fetch_audit()

    @work(thread=True, exclusive=True)
    def _fetch_audit(self) -> None:
        try:
            audit = self.ctx.client.user_audit(self.user.org_id, self.user.id)
        except EXPECTED_ERRORS as exc:
            self.app.call_from_thread(self.app.notify, sanitize(str(exc)), severity="error",
                                      markup=False)
            return
        rows = []
        for a in audit:
            if not isinstance(a, dict):
                continue
            addr = a.get("remote_addr") or a.get("remote_address")
            geo = self.ctx.geo.lookup(addr) if (self.ctx.geo and addr) else None
            rows.append({"time": fmt_ts(a.get("timestamp")), "type": a.get("type"),
                         "remote": addr, "location": geo.label if geo else "",
                         "message": a.get("message")})
        cols = [("time", "Time"), ("type", "Type"), ("remote", "Remote")]
        if self.ctx.geo is not None:
            cols.append(("location", "Location"))
        cols.append(("message", "Message"))
        self.app.call_from_thread(fill_table, self.query_one("#user-audit", DataTable),
                                  cols, rows)

    @on(Button.Pressed, "#btn-toggle")
    def toggle(self) -> None:
        u = self.user
        verb = "enable" if u.disabled else "disable"
        question = f"{verb.capitalize()} {u.org_name}/{u.name}?"
        if not u.disabled and u.sessions:
            question += f" {len(u.sessions)} live session(s) will be dropped."

        def done(confirmed: bool | None) -> None:
            if confirmed:
                self._set_disabled(not u.disabled)

        self.app.push_screen(ConfirmScreen(question), done)

    @work(thread=True, exclusive=True)
    def _set_disabled(self, disabled: bool) -> None:
        u = self.user
        try:
            self.ctx.client.set_user_disabled(u.org_id, u.id, disabled)
        except EXPECTED_ERRORS as exc:
            self.app.call_from_thread(self.app.notify, sanitize(str(exc)), severity="error",
                                      markup=False)
            return
        verb = "disabled" if disabled else "enabled"
        self.app.call_from_thread(self.app.notify, sanitize(f"{u.org_name}/{u.name} {verb}"),
                                  markup=False)
        self.app.call_from_thread(self.app.action_refresh)
        self.app.call_from_thread(self.dismiss)


class ServerScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss", "Close"), Binding("q", "dismiss", "Close")]

    def __init__(self, ctx: Ctx, server: Server, inv: Inventory):
        super().__init__()
        self.ctx = ctx
        self.server = server
        self.inv = inv

    def compose(self) -> ComposeResult:
        s = self.server
        info = Text()
        info.append(sanitize(s.name), style="bold")
        info.append("  ")
        info.append(sanitize(s.status), style=STYLE_BY_VALUE.get(s.status, "yellow"))
        info.append(f"\nNetwork: {sanitize(s.network or '-')}   Listen: "
                    f"{sanitize(s.protocol or '')}/{s.port or ''}   Uptime: "
                    f"{fmt_duration(s.uptime) if s.uptime else '-'}")
        info.append(f"\nGroups: {sanitize(', '.join(s.groups) or '(all)')}   OTP: "
                    f"{'yes' if s.otp_auth else 'no'}   SSO: {'yes' if s.sso_auth else 'no'}"
                    f"   WireGuard: {'yes' if s.wg else 'no'}")
        with Vertical(id="dialog"):
            yield Static(info)
            yield Label(Text("Connected users", style="bold"))
            yield DataTable(id="server-sessions", cursor_type="row", zebra_stripes=True)
            yield Label(Text("Server output", style="bold"))
            yield RichLog(id="server-log", markup=False, highlight=False, wrap=True,
                          max_lines=2000)
            with Horizontal(classes="buttons"):
                yield Button("Load logs", id="btn-logs")
                yield Button("Close", id="btn-close", variant="primary")

    def on_mount(self) -> None:
        now = time.time()
        pairs = sorted(((u, e) for u, e in iter_sessions(self.inv.users)
                        if e.server_id == self.server.id),
                       key=lambda p: (p[0].org_name.lower(), p[0].name.lower()))
        cols = with_geo([c for c in SESSION_COLUMNS if c[0] not in ("server", "state")],
                        self.ctx.geo is not None)
        fill_table(self.query_one("#server-sessions", DataTable), cols,
                   [session_row(u, e, now) for u, e in pairs])

    @on(Button.Pressed, "#btn-close")
    def close(self) -> None:
        self.dismiss()

    @on(Button.Pressed, "#btn-logs")
    def load_logs(self) -> None:
        self._fetch_logs()

    @work(thread=True, exclusive=True)
    def _fetch_logs(self) -> None:
        try:
            lines = self.ctx.client.server_output(self.server.id)
        except EXPECTED_ERRORS as exc:
            self.app.call_from_thread(self.app.notify, sanitize(str(exc)), severity="error",
                                      markup=False)
            return

        def show() -> None:
            log = self.query_one("#server-log", RichLog)
            log.clear()
            for line in lines[-500:]:
                log.write(Text(sanitize(line)))

        self.app.call_from_thread(show)


# ----------------------------------------------------------------------------- app


SEVERITY_OPTIONS = [(Text(s), s) for s in ("high", "medium", "low", "info")]


class PritunlTUI(App[None]):
    TITLE = "Pritunl Toolbox"
    CSS = """
    .bar { height: auto; padding: 0 1; }
    .bar Input { width: 1fr; }
    .bar Select { width: 32; }
    .bar Label { padding: 1 1 0 1; }
    .status { height: 1; padding: 0 1; color: $text-muted; }
    .status.error { color: $error; }
    #cards { height: 5; }
    .card { width: 1fr; height: 5; border: round $primary; padding: 0 1;
            content-align: center middle; text-align: center; }
    .card.alert { border: round $error; }
    #dash-tables { height: 1fr; }
    #dash-tables DataTable { width: 1fr; }
    DataTable { height: 1fr; }
    #report-overview { height: auto; padding: 0 1; }
    UserScreen, ServerScreen, ConfirmScreen { align: center middle; }
    #dialog { width: 95%; height: 92%; border: thick $primary; background: $surface;
              padding: 1 2; }
    #dialog Label { margin-top: 1; }
    #dialog RichLog { height: 1fr; border: round $panel; }
    #confirm { width: 64; height: auto; border: thick $error; background: $surface;
               padding: 1 2; }
    .buttons { height: auto; align-horizontal: right; margin-top: 1; }
    .buttons Button { margin-left: 1; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("a", "toggle_auto", "Auto-refresh"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("x", "export", "Export CSV"),
        Binding("1", "show_tab('dashboard')", "Dashboard", show=False),
        Binding("2", "show_tab('online')", "Online", show=False),
        Binding("3", "show_tab('search')", "Search", show=False),
        Binding("4", "show_tab('whois')", "Whois", show=False),
        Binding("5", "show_tab('servers')", "Servers", show=False),
        Binding("6", "show_tab('report')", "Report", show=False),
    ]

    TAB_TABLES = {"dashboard": "dash-servers", "online": "online-table",
                  "search": "search-table", "whois": "whois-table",
                  "servers": "servers-table", "report": "report-table"}
    TAB_INPUTS = {"online": "online-filter", "search": "search-input",
                  "whois": "whois-input", "report": "report-countries"}

    def __init__(self, ctx: Ctx, refresh_seconds: int = 30):
        super().__init__()
        self.ctx = ctx
        self.refresh_seconds = refresh_seconds
        self.inv: Inventory | None = None
        self.loaded_at: float | None = None
        self.auto_timer: Timer | None = None
        self.travel_events: list = []
        # per table: (columns, rows, objects behind each row) for selection and export
        self.tables: dict[str, tuple[list[Column], list[dict], list[Any]]] = {}

    # ------------------------------------------------------------------ layout

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="dashboard", id="tabs"):
            with TabPane("1 Dashboard", id="dashboard"):
                with Horizontal(id="cards"):
                    for card in ("users", "sessions", "servers", "alerts", "findings"):
                        yield Static(Text("…"), id=f"card-{card}", classes="card")
                with Horizontal(id="dash-tables"):
                    yield DataTable(id="dash-servers", cursor_type="row", zebra_stripes=True)
                    yield DataTable(id="dash-side", cursor_type="row", zebra_stripes=True)
            with TabPane("2 Online", id="online"):
                with Horizontal(classes="bar"):
                    yield Input(placeholder="filter: group:dev country:PL -platform:ios  "
                                            "(same syntax as search)", id="online-filter")
                    yield Select([], prompt="All servers", id="online-server")
                yield Static(Text(""), id="online-status", classes="status")
                yield DataTable(id="online-table", cursor_type="row", zebra_stripes=True)
            with TabPane("3 Search", id="search"):
                with Horizontal(classes="bar"):
                    yield Input(placeholder="john | 10.8.0.15 | 203.0.113.0/24 | group:devops "
                                            "status:online | inactive:90d   (Enter)",
                                id="search-input")
                    yield Label(Text("per server"))
                    yield Switch(value=False, id="search-expand")
                yield Static(Text("Enter a query and press Enter."), id="search-status",
                             classes="status")
                yield DataTable(id="search-table", cursor_type="row", zebra_stripes=True)
            with TabPane("4 Whois", id="whois"):
                with Horizontal(classes="bar"):
                    yield Input(placeholder="IP addresses or CIDRs, space separated  (Enter)",
                                id="whois-input")
                yield Static(Text("Who owns or uses an address (VPN or real IP)."),
                             id="whois-status", classes="status")
                yield DataTable(id="whois-table", cursor_type="row", zebra_stripes=True)
            with TabPane("5 Servers", id="servers"):
                yield DataTable(id="servers-table", cursor_type="row", zebra_stripes=True)
            with TabPane("6 Report", id="report"):
                with Horizontal(classes="bar"):
                    yield Input(placeholder="allowed countries, e.g. PL,DE (needs GeoIP)  "
                                            "(Enter)", id="report-countries")
                    yield Select(SEVERITY_OPTIONS, value="low", allow_blank=False,
                                 id="report-severity")
                yield Static(Text(""), id="report-overview")
                yield DataTable(id="report-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        prof = self.ctx.profile
        self.sub_title = sanitize(
            f"{prof.name} · {prof.url}{' · read-only' if prof.read_only else ''}"
            f"{' · GeoIP' if self.ctx.geo else ''}")
        self.action_refresh()

    # ------------------------------------------------------------------ data

    def action_refresh(self) -> None:
        self._load()

    @work(thread=True, exclusive=True, group="load")
    def _load(self) -> None:
        try:
            inv = self.ctx.inventory()
        except Exception as exc:  # keep the UI alive on any refresh failure
            message = str(exc) if isinstance(exc, EXPECTED_ERRORS) else \
                f"{type(exc).__name__}: {exc}"
            self.call_from_thread(self.notify, sanitize(message), title="Load failed",
                                  severity="error", markup=False)
            return
        self.call_from_thread(self._loaded, inv)

    def _loaded(self, inv: Inventory) -> None:
        self.inv = inv
        self.loaded_at = time.time()
        self.travel_events = detect(session_observations(inv.users)) if self.ctx.geo else []
        select = self.query_one("#online-server", Select)
        current = select.value
        options = [(txt(s.name), s.id) for s in sorted(inv.servers, key=lambda s: s.name)]
        select.set_options(options)
        if current in {sid for _, sid in options}:
            select.value = current
        self.update_online()
        self.update_servers()
        self.update_report()  # also refreshes the dashboard
        if self.query_one("#search-input", Input).value.strip():
            self.update_search()
        if self.query_one("#whois-input", Input).value.strip():
            self.update_whois()

    def _set_table(self, table_id: str, columns: list[Column], rows: list[dict],
                   objects: list[Any]) -> None:
        self.tables[table_id] = (columns, rows, objects)
        fill_table(self.query_one(f"#{table_id}", DataTable), columns, rows)

    def _status(self, widget_id: str, message: str, error: bool = False) -> None:
        widget = self.query_one(f"#{widget_id}", Static)
        widget.update(txt(message))
        widget.set_class(error, "error")

    @property
    def geo_on(self) -> bool:
        return self.ctx.geo is not None

    def _query(self, text: str, status_id: str, extra: Sequence[str] = ()) -> Query | None:
        try:
            query = Query.parse([text, *extra] if text.strip() else list(extra))
            if query.uses_geo and not self.geo_on:
                raise QueryError("country:/city:/asn: need a GeoIP database")
            return query
        except QueryError as exc:
            self._status(status_id, f"Query error: {exc}", error=True)
            return None

    # ------------------------------------------------------------------ views

    def update_online(self) -> None:
        if self.inv is None:
            return
        query = self._query(self.query_one("#online-filter", Input).value, "online-status",
                            ["status:online"])
        if query is None:
            return
        select = self.query_one("#online-server", Select)
        server_id = None if select.is_blank() else select.value
        pairs = [(m.user, e) for m in query.run(self.inv.users) for e in m.entries
                 if e.connected and (server_id is None or e.server_id == server_id)]
        pairs.sort(key=lambda p: (p[1].server_name.lower(), p[0].org_name.lower(),
                                  p[0].name.lower()))
        now = time.time()
        self._set_table("online-table", with_geo(SESSION_COLUMNS, self.geo_on),
                        [session_row(u, e, now) for u, e in pairs], [u for u, _ in pairs])
        self._status("online-status",
                     f"{len(pairs)} sessions · {len({u.id for u, _ in pairs})} users · "
                     f"updated {fmt_ts(self.loaded_at)}"
                     f"{' · auto-refresh on' if self.auto_timer else ''}")

    def update_search(self) -> None:
        if self.inv is None:
            return
        text = self.query_one("#search-input", Input).value
        query = self._query(text, "search-status")
        if query is None:
            return
        matches: list[Match] = sorted(query.run(self.inv.users),
                                      key=lambda m: (m.user.org_name.lower(),
                                                     m.user.name.lower()))
        now = time.time()
        if self.query_one("#search-expand", Switch).value:
            pairs = [(m.user, e) for m in matches for e in m.entries]
            self._set_table("search-table", with_geo(SESSION_COLUMNS, self.geo_on),
                            [session_row(u, e, now) for u, e in pairs], [u for u, _ in pairs])
        else:
            self._set_table("search-table", with_geo(USER_COLUMNS, self.geo_on),
                            [user_row(m, now) for m in matches], [m.user for m in matches])
        self._status("search-status", f"{len(matches)} users match: {query}")

    def update_whois(self) -> None:
        if self.inv is None:
            return
        rows, objects = [], []
        now = time.time()
        for ip in self.query_one("#whois-input", Input).value.split():
            try:
                query, vip_q = Query.parse([f"ip:{ip}"]), Query.parse([f"vip:{ip}"])
            except QueryError as exc:
                self._status("whois-status", f"{ip}: {exc}", error=True)
                return
            for m in query.run(self.inv.users):
                for e in m.entries:
                    if vip_q.entry_terms[0].entry_pred(e):
                        kind = "vpn-ip (live)" if e.connected else "vpn-ip (assigned)"
                    else:
                        kind = "real-ip"
                    rows.append({"query": ip, "match": kind, **session_row(m.user, e, now)})
                    objects.append(m.user)
        cols = with_geo([("query", "Query"), ("match", "Match"), ("org", "Org"),
                         ("user", "User"), ("email", "Email"), ("server", "Server"),
                         ("state", "State"), ("vpn_ip", "VPN IP"), ("real_ip", "Real IP"),
                         ("uptime", "Connected"), ("device", "Device")], self.geo_on)
        self._set_table("whois-table", cols, rows, objects)
        self._status("whois-status", f"{len(rows)} match(es)" if rows else "no match")

    def update_servers(self) -> None:
        if self.inv is None:
            return
        live: dict[str, int] = {}
        for _, e in iter_sessions(self.inv.users):
            live[e.server_id] = live.get(e.server_id, 0) + 1
        servers = sorted(self.inv.servers, key=lambda s: s.name.lower())
        rows = [{"name": s.name, "status": s.status, "sessions": live.get(s.id, 0),
                 "users": s.user_count, "network": s.network,
                 "listen": f"{s.protocol or ''}/{s.port or ''}",
                 "groups": s.groups or ["(all)"],
                 "2fa": "otp" if s.otp_auth else ("sso" if s.sso_auth else "no"),
                 "uptime": fmt_duration(s.uptime) if s.uptime else ""} for s in servers]
        cols = [("name", "Name"), ("status", "Status"), ("sessions", "Sessions"),
                ("users", "Users"), ("network", "Network"), ("listen", "Listen"),
                ("groups", "Groups"), ("2fa", "2FA"), ("uptime", "Uptime")]
        self._set_table("servers-table", cols, rows, servers)

    def update_report(self) -> None:
        if self.inv is None:
            return
        countries_text = self.query_one("#report-countries", Input).value
        allowed = {c.strip().upper() for c in countries_text.split(",") if c.strip()} or None
        rep = build_report(self.inv, allowed_countries=allowed if self.geo_on else None,
                           travel_events=self.travel_events)
        severity = self.query_one("#report-severity", Select).value
        limit = SEVERITY_ORDER.get(str(severity), 3)
        findings = [f for f in rep["findings"] if SEVERITY_ORDER[f["severity"]] <= limit]
        users_by_label = {f"{u.org_name}/{u.name}": u for u in self.inv.users}
        self._set_table("report-table", [("severity", "Severity"), ("check", "Check"),
                                         ("subject", "Subject"), ("detail", "Detail")],
                        findings, [users_by_label.get(f["subject"]) for f in findings])
        ov = rep["overview"]
        overview = Text()
        overview.append(f"{ov['users']} users · {ov['online_users']} online · "
                        f"{ov['sessions']} sessions · {ov['disabled_users']} disabled · "
                        f"{ov['servers_online']}/{ov['servers']} servers online")
        if allowed and not self.geo_on:
            overview.append("   (country check needs a GeoIP database)", style="yellow")
        self.query_one("#report-overview", Static).update(overview)
        self.update_dashboard(rep)

    def update_dashboard(self, rep: dict) -> None:
        ov = rep["overview"]
        counts = {s: sum(1 for f in rep["findings"] if f["severity"] == s)
                  for s in ("high", "medium")}
        disabled_online = sum(1 for f in rep["findings"]
                              if f["check"] == "disabled-user-connected")

        def card(card_id: str, value: str, label: str, alert: bool = False) -> None:
            widget = self.query_one(f"#card-{card_id}", Static)
            content = Text(value, style="bold red" if alert else "bold")
            content.append(f"\n{label}", style="dim")
            widget.update(content)
            widget.set_class(alert, "alert")

        card("users", f"{ov['online_users']} / {ov['users']}", "users online")
        card("sessions", str(ov["sessions"]), "sessions")
        card("servers", f"{ov['servers_online']} / {ov['servers']}", "servers online",
             alert=ov["servers_online"] < ov["servers"])
        card("alerts", str(disabled_online), "disabled but connected",
             alert=disabled_online > 0)
        card("findings", f"{counts['high']} high · {counts['medium']} med", "findings",
             alert=counts["high"] > 0)

        servers = sorted(self.inv.servers if self.inv else [], key=lambda s: s.name.lower())
        by_name = {r["server"]: r for r in rep["servers"]}
        server_rows = [{"server": s.name, "status": s.status,
                        "sessions": by_name.get(s.name, {}).get("sessions", 0),
                        "users": by_name.get(s.name, {}).get("users", 0),
                        "platforms": by_name.get(s.name, {}).get("platforms", [])}
                       for s in servers]
        self._set_table("dash-servers", [("server", "Server"), ("status", "Status"),
                                         ("sessions", "Sessions"), ("users", "Users"),
                                         ("platforms", "Platforms")], server_rows, servers)
        if rep["countries"]:
            self._set_table("dash-side", [("country", "Country"), ("sessions", "Sessions")],
                            rep["countries"], [None] * len(rep["countries"]))
        else:
            platforms = [{"platform": p, "sessions": n}
                         for p, n in ov["platforms"].items()]
            self._set_table("dash-side", [("platform", "Platform"), ("sessions", "Sessions")],
                            platforms, [None] * len(platforms))

    # ------------------------------------------------------------------ events

    @on(Input.Changed, "#online-filter")
    @on(Select.Changed, "#online-server")
    def _online_changed(self) -> None:
        self.update_online()

    @on(Input.Submitted, "#search-input")
    @on(Switch.Changed, "#search-expand")
    def _search_changed(self) -> None:
        self.update_search()

    @on(Input.Submitted, "#whois-input")
    def _whois_changed(self) -> None:
        self.update_whois()

    @on(Input.Submitted, "#report-countries")
    @on(Select.Changed, "#report-severity")
    def _report_changed(self) -> None:
        self.update_report()

    @on(DataTable.RowSelected)
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        table_id = event.data_table.id or ""
        if table_id not in self.tables or self.inv is None:
            return
        objects = self.tables[table_id][2]
        try:
            obj = objects[int(event.row_key.value)]
        except (TypeError, ValueError, IndexError):
            return
        if isinstance(obj, User):
            self.push_screen(UserScreen(self.ctx, obj))
        elif isinstance(obj, Server):
            self.push_screen(ServerScreen(self.ctx, obj, self.inv))

    # ------------------------------------------------------------------ actions

    def action_show_tab(self, tab: str) -> None:
        self.query_one(TabbedContent).active = tab

    def action_focus_filter(self) -> None:
        tab = self.query_one(TabbedContent).active
        if tab in self.TAB_INPUTS:
            self.query_one(f"#{self.TAB_INPUTS[tab]}", Input).focus()

    def action_toggle_auto(self) -> None:
        if self.auto_timer is None:
            self.auto_timer = self.set_interval(self.refresh_seconds, self.action_refresh)
            self.notify(f"Auto-refresh every {self.refresh_seconds}s")
        else:
            self.auto_timer.stop()
            self.auto_timer = None
            self.notify("Auto-refresh off")
        self.update_online()

    def action_export(self) -> None:
        tab = self.query_one(TabbedContent).active
        table_id = self.TAB_TABLES.get(tab)
        if not table_id or table_id not in self.tables:
            self.notify("Nothing to export here", severity="warning")
            return
        columns, rows, _ = self.tables[table_id]
        try:
            path = write_export(tab, columns, rows)
        except OSError as exc:
            self.notify(sanitize(f"Export failed: {exc}"), severity="error", markup=False)
            return
        self.notify(sanitize(f"Exported {len(rows)} rows to {path} (contains personal data)"),
                    markup=False, timeout=8)


def run_tui(ctx: Ctx, refresh_seconds: int = 30) -> None:
    PritunlTUI(ctx, refresh_seconds=refresh_seconds).run()
