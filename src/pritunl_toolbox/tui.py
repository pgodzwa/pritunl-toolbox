# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 pritunl-toolbox contributors
"""Interactive terminal UI (Textual). Strictly read-only towards Pritunl.

Navigation model
  * 1-6 or [ / ] switch tabs; switching always lands on the tab's table, so the next 1-6 works
    too. F1-F6 switch tabs from anywhere, even while typing in a box (where 1-6 are text).
  * Tables: Up/Down to move, Enter for details. Dialogs close with Esc.
  * / jumps to the tab's filter/query box. In a box, Enter applies and returns to the table,
    Esc or Down returns to the table without typing more.
  * The tab bar itself is not in the Tab-key focus cycle (click it or use 1-6), so Tab only
    moves between the controls of the current tab.
  * While a dialog is open the tab/global shortcuts are disabled, so nothing changes behind it.
  * ? shows this overview, g opens the GeoIP setup, q quits.

Security notes
  * Every cell/label is a pre-sanitised ``rich.text.Text``. Textual's DataTable parses plain
    strings as markup, and values like device names come from VPN clients.
  * Notifications are sent with ``markup=False``.
  * There are no write actions against Pritunl; the API client refuses non-GET requests.
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
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widgets import (
    Button,
    Checkbox,
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
    Tabs,
)

from pritunl_toolbox import LICENSE_NOTICE, __version__
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
from pritunl_toolbox.config import ConfigError, load_geo_settings, save_geo_settings
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
TAB_ORDER = ("dashboard", "online", "search", "whois", "servers", "report")


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
        table.move_cursor(row=min(max(cursor, 0), len(rows) - 1), animate=False)


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


# ----------------------------------------------------------------------------- widgets


class Grid(DataTable):
    """Row-cursor table whose Enter binding is visible in the footer."""

    BINDINGS = [Binding("enter", "select_cursor", "Details", show=True)]

    def __init__(self, **kwargs: Any):
        super().__init__(cursor_type="row", zebra_stripes=True, **kwargs)

    def action_select_cursor(self) -> None:
        # Enter on an empty main-screen table (e.g. Search before the first query) jumps to the
        # tab's query box, so starting a search stays a single key.
        if self.row_count == 0 and self.screen is self.app.screen_stack[0]:
            self.app.action_focus_filter()  # type: ignore[attr-defined]
            return
        super().action_select_cursor()


class FilterInput(Input):
    """Query box: Esc / Down hand focus back to the tab's table."""

    BINDINGS = [
        Binding("escape", "app.focus_table", "Back to table", show=True),
        Binding("down", "app.focus_table", "Table", show=False),
    ]


# ----------------------------------------------------------------------------- modals


HELP_TEXT = """\
Navigation
  1-6, [ ]        switch tab (lands on the tab's table)
  F1-F6           switch tab from anywhere, even while typing in a box
  Up/Down, PgUp   move in a table          Enter   open details
  /               jump to the filter/query box of the tab
  Enter in a box  apply and go back to the table (Enter on an empty table: go to the box)
  Esc             leave a box / close a dialog
  Tab             next control in the current tab

Actions
  r  refresh now          a  toggle auto-refresh
  x  export table to CSV  g  GeoIP (MaxMind GeoLite2) setup
  ?  this help            q  quit

Tips
  Dashboard: Enter on a server shows who is connected; on a country or
  platform jumps to Online filtered by it.
  Report: Enter on a finding opens the user/server it is about.
  Read-only: nothing is ever changed on the Pritunl server.
"""


class HelpScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss", "Close"),
                Binding("q,question_mark", "dismiss", "Close", show=False)]

    def compose(self) -> ComposeResult:
        with Vertical(id="help"):
            yield Static(Text("Keyboard reference", style="bold"))
            yield Static(Text(HELP_TEXT))
            yield Static(Text(f"pritunl-toolbox {__version__}\n{LICENSE_NOTICE}", style="dim"))
            with Horizontal(classes="buttons"):
                yield Button("Close", id="btn-close", variant="primary")
        yield Footer()

    @on(Button.Pressed, "#btn-close")
    def close(self) -> None:
        self.dismiss()


class UserScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss", "Close"),
                Binding("q", "dismiss", "Close", show=False),
                Binding("l", "load_audit", "Load audit log")]

    def __init__(self, ctx: Ctx, user: User):
        super().__init__()
        self.ctx = ctx
        self.user = user

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(self._info(), id="user-info")
            yield Label(Text("Servers", style="bold"))
            yield Grid(id="user-servers")
            yield Label(Text("Audit log", style="bold"))
            yield Grid(id="user-audit")
            with Horizontal(classes="buttons"):
                yield Button("Load audit log (l)", id="btn-audit")
                yield Button("Close (Esc)", id="btn-close", variant="primary")
        yield Footer()

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
        table = self.query_one("#user-servers", Grid)
        fill_table(table, cols, [session_row(self.user, e, now) for e in self.user.servers])
        table.focus()

    @on(Button.Pressed, "#btn-close")
    def close(self) -> None:
        self.dismiss()

    @on(Button.Pressed, "#btn-audit")
    def action_load_audit(self) -> None:
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

        def show() -> None:
            table = self.query_one("#user-audit", Grid)
            fill_table(table, cols, rows)
            if not rows:
                self.app.notify("Audit log is empty (is auditing enabled in Pritunl?)",
                                severity="warning")

        self.app.call_from_thread(show)


class ServerScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss", "Close"),
                Binding("q", "dismiss", "Close", show=False),
                Binding("l", "load_logs", "Load logs")]

    def __init__(self, ctx: Ctx, server: Server, inv: Inventory):
        super().__init__()
        self.ctx = ctx
        self.server = server
        self.inv = inv
        self.users: list[User] = []

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
            yield Label(Text(""), id="server-sessions-title")
            yield Grid(id="server-sessions")
            yield Label(Text("Server output", style="bold"))
            yield RichLog(id="server-log", markup=False, highlight=False, wrap=True,
                          max_lines=2000)
            with Horizontal(classes="buttons"):
                yield Button("Load logs (l)", id="btn-logs")
                yield Button("Close (Esc)", id="btn-close", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        now = time.time()
        pairs = sorted(((u, e) for u, e in iter_sessions(self.inv.users)
                        if e.server_id == self.server.id),
                       key=lambda p: (p[0].org_name.lower(), p[0].name.lower()))
        self.users = [u for u, _ in pairs]
        cols = with_geo([c for c in SESSION_COLUMNS if c[0] not in ("server", "state")],
                        self.ctx.geo is not None)
        table = self.query_one("#server-sessions", Grid)
        fill_table(table, cols, [session_row(u, e, now) for u, e in pairs])
        title = Text(f"Connected users ({len({u.id for u in self.users})} users, "
                     f"{len(pairs)} sessions)", style="bold")
        if not pairs:
            title.append("  - nobody is connected right now", style="dim")
        self.query_one("#server-sessions-title", Label).update(title)
        table.focus()

    @on(DataTable.RowSelected, "#server-sessions")
    def open_user(self, event: DataTable.RowSelected) -> None:
        event.stop()
        try:
            self.app.push_screen(UserScreen(self.ctx, self.users[int(event.row_key.value)]))
        except (TypeError, ValueError, IndexError):
            pass

    @on(Button.Pressed, "#btn-close")
    def close(self) -> None:
        self.dismiss()

    @on(Button.Pressed, "#btn-logs")
    def action_load_logs(self) -> None:
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


class GeoSetupScreen(ModalScreen[bool]):
    """Form version of `pritunl-toolbox geo setup` (talks only to MaxMind)."""

    BINDINGS = [Binding("escape", "dismiss(False)", "Close")]

    def __init__(self, ctx: Ctx):
        super().__init__()
        self.ctx = ctx
        from pritunl_toolbox import geoinstall as gi

        self.gi = gi
        self.settings = load_geo_settings()
        try:
            self.stored = gi.load_credentials(self.settings)
        except (gi.GeoInstallError, ConfigError):
            self.stored = None
        self.installed = False

    def compose(self) -> ComposeResult:
        gi = self.gi
        intro = Text()
        intro.append("MaxMind GeoLite2 setup\n", style="bold")
        intro.append("Adds country, city and provider (ASN) to connection IPs. Lookups stay on "
                     "this machine; only the download talks to MaxMind (HTTPS). Nothing is "
                     "changed on the Pritunl server.\n\n")
        intro.append(f"1. Free account:  {gi.SIGNUP_URL}\n")
        intro.append(f"2. License key:   {gi.LICENSE_KEY_URL}\n")
        intro.append("   (the account ID is shown on that page; the key only once)")
        editions = self.settings.get("maxmind_editions") or list(gi.DEFAULT_EDITIONS)
        with VerticalScroll(id="dialog"):
            yield Static(intro)
            yield Label(Text("MaxMind account ID"))
            yield Input(value=self.stored.account_id if self.stored else "",
                        placeholder="e.g. 123456", restrict=r"[0-9]*", id="geo-account")
            yield Label(Text("License key"))
            yield Input(password=True, id="geo-key",
                        placeholder="stored - leave empty to reuse" if self.stored
                        else "paste the license key")
            yield Label(Text("Databases"))
            with Horizontal(classes="checks"):
                yield Checkbox("City (needed for travel checks)",
                               "GeoLite2-City" in editions, id="ed-city")
                yield Checkbox("ASN / provider", "GeoLite2-ASN" in editions, id="ed-asn")
                yield Checkbox("Country only", "GeoLite2-Country" in editions,
                               id="ed-country")
            yield Label(Text("Install directory"))
            yield Input(value=str(self.settings.get("dir") or gi.default_install_dir()),
                        id="geo-dir")
            yield Checkbox("Save credentials (config file, mode 600) for 'geo update'", True,
                           id="geo-store")
            yield RichLog(id="geo-log", markup=False, highlight=False, wrap=True,
                          max_lines=200)
            with Horizontal(classes="buttons"):
                yield Button("Download & install", id="btn-install", variant="primary")
                yield Button("Close (Esc)", id="btn-close")
        yield Footer()

    def on_mount(self) -> None:
        target = "#geo-key" if self.stored or self.query_one("#geo-account", Input).value \
            else "#geo-account"
        self.query_one(target, Input).focus()

    def _log(self, message: str) -> None:
        self.query_one("#geo-log", RichLog).write(Text(sanitize(message)))

    @on(Button.Pressed, "#btn-close")
    def close(self) -> None:
        self.dismiss(self.installed)

    @on(Input.Submitted)
    def _submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.focus_next()

    @on(Button.Pressed, "#btn-install")
    def start(self) -> None:
        gi = self.gi
        try:
            account = gi.validate_account_id(self.query_one("#geo-account", Input).value)
            key_value = self.query_one("#geo-key", Input).value
            if not key_value and self.stored and self.stored.account_id == account:
                key = self.stored.license_key
            else:
                key = gi.validate_license_key(key_value)
        except gi.GeoInstallError as exc:
            self._log(f"✗ {exc}")
            return
        editions = [ed for wid, ed in (("#ed-city", "GeoLite2-City"),
                                       ("#ed-asn", "GeoLite2-ASN"),
                                       ("#ed-country", "GeoLite2-Country"))
                    if self.query_one(wid, Checkbox).value]
        if "GeoLite2-City" in editions and "GeoLite2-Country" in editions:
            editions.remove("GeoLite2-Country")  # City already contains the country
        if not editions:
            self._log("✗ select at least one database")
            return
        dest = Path(self.query_one("#geo-dir", Input).value or
                    gi.default_install_dir()).expanduser()
        store = self.query_one("#geo-store", Checkbox).value
        self.query_one("#btn-install", Button).disabled = True
        self._log(f"Downloading {', '.join(editions)} to {dest} ...")
        self._install(gi.Credentials(account, key), editions, dest, store)

    @work(thread=True, exclusive=True)
    def _install(self, creds, editions: list[str], dest: Path, store: bool) -> None:
        gi = self.gi
        last: dict[str, int] = {}

        def progress(edition: str, done: int, total: int | None) -> None:
            pct = int(done * 100 / total) if total else None
            step = pct // 25 if pct is not None else done // (20 * 1024 * 1024)
            if last.get(edition) != step:
                last[edition] = step
                shown = f"{pct}%" if pct is not None else f"{done // 1024 // 1024} MB"
                self.app.call_from_thread(self._log, f"  {edition}: {shown}")

        try:
            results = gi.install(editions, creds, dest, force=True, progress=progress)
            values = gi.geo_settings_for(results, dest, editions)
            values["maxmind_account_id"] = creds.account_id if store else None
            values["maxmind_license_key"] = creds.license_key if store else None
            path = save_geo_settings(values)
        except (gi.GeoInstallError, ConfigError, OSError) as exc:
            self.app.call_from_thread(self._log, f"✗ {exc}")
            self.app.call_from_thread(self._enable_install)
            return
        self.ctx.reset_geo()

        def done() -> None:
            for r in results:
                self._log(f"✓ {r.edition}: {r.path} (data from {fmt_ts(r.build_epoch)})")
            self._log(f"Settings saved to {path}")
            if store:
                self._log("Keep it fresh (MaxMind updates twice a week), e.g. cron:")
                self._log(f"  {gi.cron_line()}")
            self.installed = True
            self.app.geo_changed()  # type: ignore[attr-defined]
            self._enable_install()

        self.app.call_from_thread(done)

    def _enable_install(self) -> None:
        self.query_one("#btn-install", Button).disabled = False


# ----------------------------------------------------------------------------- app


SEVERITY_OPTIONS = [(Text(s), s) for s in ("high", "medium", "low", "info")]
# Actions that must not fire while a dialog is open (they would act on the hidden screen).
# 'quit' too: in a dialog 'q' closes the dialog (Ctrl+Q still quits the app).
MAIN_SCREEN_ACTIONS = {"show_tab", "prev_tab", "next_tab", "focus_filter", "focus_table",
                       "export", "toggle_auto", "refresh", "geo_setup", "help", "quit"}


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
    #dash-servers { width: 2fr; }
    #dash-side { width: 1fr; }
    DataTable { height: 1fr; }
    DataTable:focus { border: tall $accent; }
    #report-overview { height: auto; padding: 0 1; }
    UserScreen, ServerScreen, HelpScreen, GeoSetupScreen { align: center middle; }
    #dialog { width: 95%; height: 92%; border: thick $primary; background: $surface;
              padding: 1 2; }
    #dialog Label { margin-top: 1; }
    #dialog RichLog { height: 1fr; min-height: 6; border: round $panel; }
    GeoSetupScreen #dialog { width: 100; }
    GeoSetupScreen RichLog { height: 8; }
    .checks { height: auto; }
    #help { width: 80; height: auto; border: thick $primary; background: $surface;
            padding: 1 2; }
    .buttons { height: auto; align-horizontal: right; margin-top: 1; }
    .buttons Button { margin-left: 1; }
    """
    BINDINGS = [
        Binding("1", "show_tab('dashboard')", "Tabs", key_display="1-6/F1-F6"),
        Binding("2", "show_tab('online')", "Online", show=False),
        Binding("3", "show_tab('search')", "Search", show=False),
        Binding("4", "show_tab('whois')", "Whois", show=False),
        Binding("5", "show_tab('servers')", "Servers", show=False),
        Binding("6", "show_tab('report')", "Report", show=False),
        # F-keys are priority bindings: they switch tabs even while a text box has focus.
        *(Binding(f"f{i}", f"show_tab('{tab}')", tab.capitalize(), show=False, priority=True)
          for i, tab in enumerate(TAB_ORDER, start=1)),
        Binding("left_square_bracket", "prev_tab", "Previous tab", show=False),
        Binding("right_square_bracket", "next_tab", "Next tab", show=False),
        Binding("slash", "focus_filter", "Filter"),
        Binding("r", "refresh", "Refresh"),
        Binding("a", "toggle_auto", "Auto-refresh"),
        Binding("x", "export", "Export"),
        Binding("g", "geo_setup", "GeoIP"),
        Binding("question_mark", "help", "Help"),
        Binding("q", "quit", "Quit"),
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
        # per table: (columns, rows, object behind each row) for selection and export
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
                    yield Grid(id="dash-servers")
                    yield Grid(id="dash-side")
            with TabPane("2 Online", id="online"):
                with Horizontal(classes="bar"):
                    yield FilterInput(placeholder="filter: group:dev country:PL -platform:ios  "
                                                  "(same syntax as search)", id="online-filter")
                    yield Select([], prompt="All servers", id="online-server")
                yield Static(Text(""), id="online-status", classes="status")
                yield Grid(id="online-table")
            with TabPane("3 Search", id="search"):
                with Horizontal(classes="bar"):
                    yield FilterInput(placeholder="john | 10.8.0.15 | 203.0.113.0/24 | "
                                                  "group:devops status:online | inactive:90d",
                                      id="search-input")
                    yield Label(Text("per server"))
                    yield Switch(value=False, id="search-expand")
                yield Static(Text("Press / or Enter to type a query, Enter to run it "
                                  "(empty = everyone)."), id="search-status", classes="status")
                yield Grid(id="search-table")
            with TabPane("4 Whois", id="whois"):
                with Horizontal(classes="bar"):
                    yield FilterInput(placeholder="IP addresses or CIDRs, space separated, "
                                                  "then Enter", id="whois-input")
                yield Static(Text("Who owns or uses an address (VPN or real IP). Press / or Enter "
                                  "to type IPs."), id="whois-status", classes="status")
                yield Grid(id="whois-table")
            with TabPane("5 Servers", id="servers"):
                yield Static(Text("Enter on a server shows who is connected."),
                             classes="status")
                yield Grid(id="servers-table")
            with TabPane("6 Report", id="report"):
                with Horizontal(classes="bar"):
                    yield FilterInput(placeholder="allowed countries, e.g. PL,DE (needs GeoIP), "
                                                  "then Enter", id="report-countries")
                    yield Select(SEVERITY_OPTIONS, value="low", allow_blank=False,
                                 id="report-severity")
                yield Static(Text(""), id="report-overview")
                yield Grid(id="report-table")
        yield Footer()

    def on_mount(self) -> None:
        # The tab bar is clickable but not in the Tab-key cycle: 1-6 / [ ] switch tabs.
        for tabs in self.query(Tabs):
            tabs.can_focus = False
        self._update_subtitle()
        self.action_focus_table()
        self.action_refresh()
        if self.ctx.geo is None:
            self.notify("GeoIP is not configured - press g to set up MaxMind GeoLite2",
                        timeout=6)

    def _update_subtitle(self) -> None:
        prof = self.ctx.profile
        self.sub_title = sanitize(f"{prof.name} · {prof.url} · read-only"
                                  f"{' · GeoIP' if self.ctx.geo else ''}")

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action in MAIN_SCREEN_ACTIONS and len(self.screen_stack) > 1:
            return False
        return True

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
        if self.query_one("#search-input", Input).value.strip() or \
                "search-table" in self.tables:
            self.update_search()
        if self.query_one("#whois-input", Input).value.strip():
            self.update_whois()

    def geo_changed(self) -> None:
        self._update_subtitle()
        self.action_refresh()

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
                raise QueryError("country:/city:/asn: need a GeoIP database (press g)")
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
                     f"{' · auto-refresh on' if self.auto_timer else ''}"
                     "  ·  Enter: details  /: filter")

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

    def _server_rows(self) -> tuple[list[Server], dict[str, dict[str, Any]]]:
        servers = sorted(self.inv.servers if self.inv else [], key=lambda s: s.name.lower())
        stats: dict[str, dict[str, Any]] = {s.id: {"sessions": 0, "users": set(),
                                                   "platforms": {}} for s in servers}
        for u, e in iter_sessions(self.inv.users if self.inv else []):
            st = stats.setdefault(e.server_id, {"sessions": 0, "users": set(), "platforms": {}})
            st["sessions"] += 1
            st["users"].add(u.id)
            p = e.platform or "unknown"
            st["platforms"][p] = st["platforms"].get(p, 0) + 1
        return servers, stats

    def update_servers(self) -> None:
        if self.inv is None:
            return
        servers, stats = self._server_rows()
        rows = [{"name": s.name, "status": s.status, "sessions": stats[s.id]["sessions"],
                 "online": len(stats[s.id]["users"]), "users": s.user_count,
                 "network": s.network, "listen": f"{s.protocol or ''}/{s.port or ''}",
                 "groups": s.groups or ["(all)"],
                 "2fa": "otp" if s.otp_auth else ("sso" if s.sso_auth else "no"),
                 "uptime": fmt_duration(s.uptime) if s.uptime else ""} for s in servers]
        cols = [("name", "Name"), ("status", "Status"), ("online", "Online users"),
                ("sessions", "Sessions"), ("users", "Users"), ("network", "Network"),
                ("listen", "Listen"), ("groups", "Groups"), ("2fa", "2FA"),
                ("uptime", "Uptime")]
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
        servers_by_name = {s.name: s for s in self.inv.servers}

        def target(f: dict) -> Any:
            subject = f["subject"]
            if subject in users_by_label:
                return users_by_label[subject]
            if subject in servers_by_name:
                return servers_by_name[subject]
            if f["check"] == "duplicate-vpn-ip":  # "server ip"
                return ("whois", subject.rsplit(" ", 1)[-1])
            if f["check"] == "shared-source-ip":
                return ("whois", subject)
            return None

        self._set_table("report-table", [("severity", "Severity"), ("check", "Check"),
                                         ("subject", "Subject"), ("detail", "Detail")],
                        findings, [target(f) for f in findings])
        ov = rep["overview"]
        overview = Text()
        overview.append(f"{ov['users']} users · {ov['online_users']} online · "
                        f"{ov['sessions']} sessions · {ov['disabled_users']} disabled · "
                        f"{ov['servers_online']}/{ov['servers']} servers online")
        if allowed and not self.geo_on:
            overview.append("   (country check needs GeoIP - press g)", style="yellow")
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

        servers, stats = self._server_rows()
        server_rows = [{"server": s.name, "status": s.status,
                        "users": len(stats[s.id]["users"]),
                        "sessions": stats[s.id]["sessions"],
                        "platforms": [f"{p}: {n}" for p, n in
                                      sorted(stats[s.id]["platforms"].items(),
                                             key=lambda kv: -kv[1])]}
                       for s in servers]
        self._set_table("dash-servers", [("server", "Server"), ("status", "Status"),
                                         ("users", "Online users"), ("sessions", "Sessions"),
                                         ("platforms", "Platforms")], server_rows, servers)
        if rep["countries"]:
            self._set_table("dash-side", [("country", "Country"), ("sessions", "Sessions")],
                            rep["countries"],
                            [("filter", f"country:{c['country']}")
                             if len(c["country"]) == 2 else None for c in rep["countries"]])
        else:
            platforms = [{"platform": p, "sessions": n}
                         for p, n in ov["platforms"].items()]
            self._set_table("dash-side", [("platform", "Platform"), ("sessions", "Sessions")],
                            platforms, [("filter", f"platform:={p['platform']}")
                                        for p in platforms])

    # ------------------------------------------------------------------ events

    @on(TabbedContent.TabActivated)
    def _tab_activated(self) -> None:
        # Tab switched by mouse click: move focus into the newly shown tab.
        self.call_after_refresh(self._focus_tab_default)

    def _focus_in_active_tab(self) -> bool:
        tabbed = self.query_one(TabbedContent)
        pane = tabbed.get_pane(tabbed.active) if tabbed.active else None
        focused = self.focused
        return bool(pane and focused and pane in focused.ancestors_with_self)

    def _focus_tab_default(self, force: bool = False) -> None:
        # Never steal focus the user already moved inside this tab (e.g. '6' then '/').
        if not force and self._focus_in_active_tab():
            return
        # Always land on the table: digits typed into a box would not switch tabs any more.
        self.action_focus_table()

    @on(Input.Changed, "#online-filter")
    @on(Select.Changed, "#online-server")
    def _online_changed(self) -> None:
        self.update_online()

    @on(Input.Submitted, "#online-filter")
    def _online_submitted(self) -> None:
        self.update_online()
        self.action_focus_table()

    @on(Input.Submitted, "#search-input")
    def _search_submitted(self) -> None:
        self.update_search()
        self.action_focus_table()

    @on(Switch.Changed, "#search-expand")
    def _search_changed(self) -> None:
        self.update_search()

    @on(Input.Submitted, "#whois-input")
    def _whois_submitted(self) -> None:
        self.update_whois()
        self.action_focus_table()

    @on(Input.Submitted, "#report-countries")
    def _report_submitted(self) -> None:
        self.update_report()
        self.action_focus_table()

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
        elif isinstance(obj, tuple) and obj[0] == "filter":
            self.query_one("#online-filter", Input).value = obj[1]
            self.action_show_tab("online")
        elif isinstance(obj, tuple) and obj[0] == "whois":
            self.query_one("#whois-input", Input).value = obj[1]
            self.update_whois()
            self.action_show_tab("whois")

    # ------------------------------------------------------------------ actions

    def action_show_tab(self, tab: str) -> None:
        tabbed = self.query_one(TabbedContent)
        if tabbed.active != tab:
            # Drop focus first: TabbedContent re-activates the pane of the focused widget,
            # so focus left behind in the old (now hidden) tab would flip it back.
            self.screen.set_focus(None)
            tabbed.active = tab
            self.refresh()
        self._focus_tab_default(force=True)

    def _step_tab(self, step: int) -> None:
        current = self.query_one(TabbedContent).active
        index = TAB_ORDER.index(current) if current in TAB_ORDER else 0
        self.action_show_tab(TAB_ORDER[(index + step) % len(TAB_ORDER)])

    def action_prev_tab(self) -> None:
        self._step_tab(-1)

    def action_next_tab(self) -> None:
        self._step_tab(1)

    def action_focus_table(self) -> None:
        tab = self.query_one(TabbedContent).active
        table_id = self.TAB_TABLES.get(tab)
        if table_id:
            self.query_one(f"#{table_id}", DataTable).focus()

    def action_focus_filter(self) -> None:
        tab = self.query_one(TabbedContent).active
        if tab in self.TAB_INPUTS:
            self.query_one(f"#{self.TAB_INPUTS[tab]}", Input).focus()
        else:
            self.notify("This tab has no filter", severity="warning", timeout=2)

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_geo_setup(self) -> None:
        self.push_screen(GeoSetupScreen(self.ctx))

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
