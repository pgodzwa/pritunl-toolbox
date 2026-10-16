import os
import stat

import pytest
from rich.text import Text
from textual.widgets import Button, DataTable, Input, Tabs

from pritunl_toolbox.context import Ctx
from pritunl_toolbox.tui import (
    GeoSetupScreen,
    HelpScreen,
    PritunlTUI,
    ServerScreen,
    UserScreen,
    write_export,
)

SIZE = (180, 50)


async def loaded(pilot):
    await pilot.app.workers.wait_for_complete()
    await pilot.pause()


def rows(app_or_screen, table_id):
    table = app_or_screen.query_one(f"#{table_id}", DataTable)
    return [table.get_row_at(i) for i in range(table.row_count)]


def focused_id(app):
    return app.focused.id if app.focused else None


def active_tab(app):
    return app.query_one("#tabs").active


# ----------------------------------------------------------------------------- content


async def test_dashboard_and_online_content(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        online = rows(app, "online-table")
        assert len(online) == 4
        assert all(isinstance(c, Text) for row in online for c in row)
        # client-controlled device name is shown literally, never as markup
        assert any(c.plain == "[red]evil" for row in online for c in row)
        dash = {r[0].plain: r for r in rows(app, "dash-servers")}
        assert dash["prod-vpn"][2].plain == "3"  # online users per server
        assert "read-only" in app.sub_title


async def test_server_from_dashboard_lists_connected_users(fake_api):
    """Regression: live sessions carry Pritunl session ids, not server ids."""
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        assert focused_id(app) == "dash-servers"
        await pilot.press("enter")  # first row: prod-vpn
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, ServerScreen) and screen.server.name == "prod-vpn"
        users = sorted(r[1].plain for r in rows(screen, "server-sessions"))
        assert users == ["alice", "carol", "dave"]
        assert focused_id(app) == "server-sessions"
        await pilot.press("enter")  # drill into a user
        await pilot.pause()
        assert isinstance(app.screen, UserScreen)
        await pilot.press("escape", "escape")
        await pilot.pause()
        assert not isinstance(app.screen, (UserScreen, ServerScreen))
        assert focused_id(app) == "dash-servers"


async def test_servers_tab_and_logs_are_sanitised(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        await pilot.press("5")
        await pilot.pause()
        assert focused_id(app) == "servers-table"
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, ServerScreen)
        await pilot.press("l")
        await loaded(pilot)
        log = app.screen.query_one("#server-log")
        text = "\n".join(strip.text for strip in log.lines)
        assert "\x1b" not in text and "badred" in text


async def test_no_write_controls_anywhere(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        await pilot.press("2", "enter")
        await pilot.pause()
        assert isinstance(app.screen, UserScreen)
        labels = [str(b.label) for b in app.screen.query(Button)]
        assert not [lbl for lbl in labels if "able" in lbl.lower()]  # no Enable/Disable
        await pilot.press("l")  # audit log is a read
        await loaded(pilot)
        assert rows(app.screen, "user-audit")
    assert fake_api.writes == []


# ----------------------------------------------------------------------------- navigation


async def test_tab_keys_move_focus_into_tab(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        assert all(not t.can_focus for t in app.query(Tabs))  # not in Tab-key cycle
        expected = {"2": ("online", "online-table"), "3": ("search", "search-input"),
                    "4": ("whois", "whois-input"), "5": ("servers", "servers-table"),
                    "6": ("report", "report-table"), "1": ("dashboard", "dash-servers")}
        for key, (tab, widget) in expected.items():
            await pilot.press(key)
            await pilot.pause()
            assert (active_tab(app), focused_id(app)) == (tab, widget), key
            if widget.endswith("input"):
                await pilot.press("escape")  # digits would be typed into the box
                await pilot.pause()
                assert focused_id(app) == f"{tab}-table"
        await pilot.press("right_square_bracket")
        await pilot.pause()
        assert active_tab(app) == "online"
        await pilot.press("left_square_bracket", "left_square_bracket")
        await pilot.pause()
        assert active_tab(app) == "report"


async def test_filter_box_flow(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        await pilot.press("2", "slash")
        await pilot.pause()
        assert focused_id(app) == "online-filter"
        await pilot.press(*"carol")
        await pilot.pause()
        assert len(rows(app, "online-table")) == 1  # filters while typing
        await pilot.press("enter")
        await pilot.pause()
        assert focused_id(app) == "online-table"
        await pilot.press("slash", "escape")
        await pilot.pause()
        assert focused_id(app) == "online-table"
        await pilot.press("slash", "down")
        await pilot.pause()
        assert focused_id(app) == "online-table"


async def test_search_and_whois_flow(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        await pilot.press("3")
        await pilot.pause()
        assert focused_id(app) == "search-input"
        await pilot.press(*"group:dev", "enter")
        await pilot.pause()
        assert focused_id(app) == "search-table" and len(rows(app, "search-table")) == 2
        await pilot.press("slash", "ctrl+u", *"bogus:1", "enter")
        await pilot.pause()
        assert "error" in app.query_one("#search-status").classes

        await pilot.press("escape", "4")
        await pilot.pause()
        assert focused_id(app) == "whois-input"
        await pilot.press(*"10.8.0.3", "enter")
        await pilot.pause()
        assert len(rows(app, "whois-table")) == 2 and focused_id(app) == "whois-table"


async def test_dialog_blocks_global_keys(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        await pilot.press("2", "enter")
        await pilot.pause()
        assert isinstance(app.screen, UserScreen)
        await pilot.press("3", "x", "g")  # must not switch tab / export / open geo behind
        await pilot.pause()
        assert isinstance(app.screen, UserScreen) and active_tab(app) == "online"
        await pilot.press("escape")
        await pilot.pause()
        assert focused_id(app) == "online-table"
        await pilot.press("enter", "q")  # 'q' in a dialog closes it, it does not quit
        await pilot.pause()
        assert app.is_running and not isinstance(app.screen, UserScreen)


async def test_dashboard_side_and_report_rows_jump(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        app.set_focus(app.query_one("#dash-side"))
        await pilot.press("enter")  # platform row -> Online filtered by that platform
        await pilot.pause()
        assert active_tab(app) == "online"
        assert app.query_one("#online-filter", Input).value.startswith("platform:=")
        assert len(rows(app, "online-table")) >= 1

        await pilot.press("6")
        await pilot.pause()
        table = app.query_one("#report-table", DataTable)
        checks = [r[1].plain for r in rows(app, "report-table")]
        table.move_cursor(row=checks.index("duplicate-vpn-ip"))
        await pilot.press("enter")
        await pilot.pause()
        assert active_tab(app) == "whois"
        assert app.query_one("#whois-input", Input).value == "10.8.0.3"


async def test_help_and_geo_dialogs_open_and_close(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        await pilot.press("question_mark")
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape", "g")
        await pilot.pause()
        assert isinstance(app.screen, GeoSetupScreen)
        assert focused_id(app) == "geo-account"
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, GeoSetupScreen)


# ----------------------------------------------------------------------------- export / geo


async def test_export_is_private(fake_api, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    app = PritunlTUI(Ctx())
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        await pilot.press("2", "x")
        await pilot.pause()
    export_dir = tmp_path / "pritunl-toolbox-exports"
    files = list(export_dir.iterdir())
    assert len(files) == 1
    assert stat.S_IMODE(os.stat(export_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(files[0]).st_mode) == 0o600
    assert "carol" in files[0].read_text()


def test_export_refuses_symlinked_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "pritunl-toolbox-exports").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError, match="symlink"):
        write_export("online", [("a", "A")], [{"a": 1}])


async def test_geo_columns_in_tui(fake_api, fake_geo):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=(200, 50)) as pilot:
        await loaded(pilot)
        table = app.query_one("#online-table", DataTable)
        headers = [str(col.label) for col in table.columns.values()]
        assert "Location" in headers and "ASN" in headers
        await pilot.press("6", "slash", *"PL", "enter")
        await pilot.pause()
        checks = [r[1].plain for r in rows(app, "report-table")]
        assert "unexpected-country" in checks and "impossible-travel" in checks
        # country rows on the dashboard jump to Online filtered by country
        await pilot.press("1")
        app.set_focus(app.query_one("#dash-side"))
        await pilot.press("enter")
        await pilot.pause()
        assert app.query_one("#online-filter", Input).value.startswith("country:")


async def test_geo_setup_screen_installs_and_enables_geo(fake_api, monkeypatch, tmp_path):
    import mmdb_util

    from pritunl_toolbox import geoinstall as gi

    def fake_install(editions, creds, dest, **kw):
        assert creds.account_id == "123456" and creds.license_key == "abcdefghijklmnop_mmk"
        dest.mkdir(parents=True, exist_ok=True)
        out = []
        for ed in editions:
            path = dest / f"{ed}.mmdb"
            record = ({"autonomous_system_number": 5617, "autonomous_system_organization": "X"}
                      if ed == "GeoLite2-ASN" else {"country": {"iso_code": "PL"}})
            path.write_bytes(mmdb_util.build_mmdb(record, database_type=ed))
            out.append(gi.InstallResult(ed, path, 1_760_000_000))
        return out

    monkeypatch.setattr(gi, "install", fake_install)
    ctx = Ctx()
    app = PritunlTUI(ctx)
    async with app.run_test(size=SIZE) as pilot:
        await loaded(pilot)
        assert ctx.geo is None
        await pilot.press("g")
        await pilot.pause()
        screen = app.screen
        screen.query_one("#geo-account", Input).value = "123456"
        screen.query_one("#geo-key", Input).value = "abcdefghijklmnop_mmk"
        screen.query_one("#geo-dir", Input).value = str(tmp_path / "GeoIP")
        await pilot.click("#btn-install")
        await loaded(pilot)
        assert screen.installed
        assert ctx.geo is not None and "GeoIP" in app.sub_title
    from pritunl_toolbox.config import load_geo_settings

    settings = load_geo_settings()
    assert settings["city"].endswith("GeoLite2-City.mmdb")
    assert settings["maxmind_license_key"] == "abcdefghijklmnop_mmk"
