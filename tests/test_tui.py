import os
import stat

from rich.text import Text
from textual.widgets import Button, DataTable, Input

from pritunl_toolbox.context import Ctx
from pritunl_toolbox.tui import ConfirmScreen, PritunlTUI, ServerScreen, UserScreen


async def loaded(pilot):
    await pilot.app.workers.wait_for_complete()
    await pilot.pause()


def cells(app, table_id):
    table = app.query_one(f"#{table_id}", DataTable)
    return [table.get_row_at(i) for i in range(table.row_count)]


async def test_dashboard_and_online(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=(180, 50)) as pilot:
        await loaded(pilot)
        rows = cells(app, "online-table")
        assert len(rows) == 4
        assert all(isinstance(c, Text) for row in rows for c in row)
        # client-controlled device name is shown literally, never as markup
        assert any(c.plain == "[red]evil" for row in rows for c in row)
        assert len(cells(app, "dash-servers")) == 2

        await pilot.press("2")
        app.query_one("#online-filter", Input).value = "group:contractors"
        await pilot.pause()
        assert len(cells(app, "online-table")) == 1


async def test_search_whois_and_errors(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=(180, 50)) as pilot:
        await loaded(pilot)
        await pilot.press("3")
        search = app.query_one("#search-input", Input)
        search.value = "group:dev"
        await search.action_submit()
        await pilot.pause()
        assert len(cells(app, "search-table")) == 2

        search.value = "bogus:1"
        await search.action_submit()
        await pilot.pause()
        assert "error" in app.query_one("#search-status").classes

        whois = app.query_one("#whois-input", Input)
        whois.value = "10.8.0.3"
        await whois.action_submit()
        await pilot.pause()
        assert len(cells(app, "whois-table")) == 2


async def test_select_user_read_only_blocks_toggle(fake_api, monkeypatch):
    monkeypatch.setenv("PRITUNL_READ_ONLY", "true")
    app = PritunlTUI(Ctx())
    async with app.run_test(size=(180, 50)) as pilot:
        await loaded(pilot)
        await pilot.press("2")
        app.query_one("#online-table", DataTable).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, UserScreen)
        assert app.screen.query_one("#btn-toggle", Button).disabled
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, UserScreen)


async def test_disable_user_with_confirmation(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=(180, 50)) as pilot:
        await loaded(pilot)
        await pilot.press("2")
        app.query_one("#online-table", DataTable).focus()
        await pilot.press("enter")  # first row: carol (Contractors), already disabled
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, UserScreen) and screen.user.name == "carol"
        await pilot.click("#btn-toggle")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        await pilot.click("#no")
        await pilot.pause()
        assert fake_api.puts == []
        await pilot.click("#btn-toggle")
        await pilot.pause()
        await pilot.click("#yes")
        await loaded(pilot)
        assert fake_api.puts == [("/user/org2/u_carol", {"disabled": False})]


async def test_server_screen_logs_are_sanitised(fake_api):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=(180, 50)) as pilot:
        await loaded(pilot)
        await pilot.press("5")
        app.query_one("#servers-table", DataTable).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, ServerScreen)
        await pilot.click("#btn-logs")
        await loaded(pilot)
        log = app.screen.query_one("#server-log")
        text = "\n".join(strip.text for strip in log.lines)
        assert "\x1b" not in text and "badred" in text


async def test_export_is_private(fake_api, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    app = PritunlTUI(Ctx())
    async with app.run_test(size=(180, 50)) as pilot:
        await loaded(pilot)
        await pilot.press("2")
        app.query_one("#online-table", DataTable).focus()
        await pilot.press("x")
        await pilot.pause()
    export_dir = tmp_path / "pritunl-toolbox-exports"
    files = list(export_dir.iterdir())
    assert len(files) == 1
    assert stat.S_IMODE(os.stat(export_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(files[0]).st_mode) == 0o600
    assert "carol" in files[0].read_text()


async def test_geo_columns_in_tui(fake_api, fake_geo):
    app = PritunlTUI(Ctx())
    async with app.run_test(size=(200, 50)) as pilot:
        await loaded(pilot)
        table = app.query_one("#online-table", DataTable)
        headers = [str(col.label) for col in table.columns.values()]
        assert "Location" in headers and "ASN" in headers
        await pilot.press("6")
        report = app.query_one("#report-countries", Input)
        report.value = "PL"
        await report.action_submit()
        await pilot.pause()
        checks = [r[1].plain for r in cells(app, "report-table")]
        assert "unexpected-country" in checks and "impossible-travel" in checks


def test_export_refuses_symlinked_dir(monkeypatch, tmp_path):
    import pytest

    from pritunl_toolbox.tui import write_export

    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "pritunl-toolbox-exports").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError, match="symlink"):
        write_export("online", [("a", "A")], [{"a": 1}])
