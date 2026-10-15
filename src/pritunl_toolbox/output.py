"""Rendering helpers: rich tables, JSON and CSV.

Many displayed values are controlled by end users or their VPN clients (user names, device names,
platform strings, server log lines). They are treated as untrusted:
  * control characters / ANSI escapes are stripped so they cannot rewrite the terminal,
  * cells are rich ``Text`` objects, so ``[markup]`` is never interpreted,
  * CSV cells that a spreadsheet would treat as formulas are neutralised.
"""

from __future__ import annotations

import csv
import json
import re
import sys
import time
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

FORMATS = ("table", "json", "csv")

console = Console(highlight=False, soft_wrap=False)
err_console = Console(stderr=True, highlight=False)

_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def sanitize(value: Any, keep_newlines: bool = False) -> str:
    if value is None:
        return ""
    text = _ANSI.sub("", str(value))
    if not keep_newlines:
        text = text.replace("\n", " ")
    return _CTRL.sub("", text)


def csv_safe(value: str) -> str:
    if value and value.startswith(_CSV_FORMULA):
        return "'" + value
    return value


def fmt_ts(epoch: int | float | None) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")


def iso_ts(epoch: int | float | None) -> str | None:
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def fmt_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return ""
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d{hours}h"
    if hours:
        return f"{hours}h{minutes:02d}m"
    return f"{minutes}m"


def fmt_ago(epoch: int | float | None, now: float | None = None) -> str:
    if not epoch:
        return "never"
    return fmt_duration((now or time.time()) - epoch) + " ago"


Column = tuple[str, str]  # (row key, header)


def _cell(value: Any, sep: str) -> str:
    if isinstance(value, (list, tuple, set)):
        return sep.join(sanitize(v) for v in value if v not in (None, ""))
    if isinstance(value, bool):
        return "yes" if value else "no"
    return sanitize(value)


STYLE_BY_VALUE = {
    "online": "green", "offline": "dim", "disabled": "red", "disabled-online": "bold red",
    "pending": "yellow",
}


def render_table(rows: Sequence[dict], columns: Sequence[Column], title: str | None = None,
                 out: Console | None = None) -> None:
    out = out or console
    table = Table(title=sanitize(title) if title else None, header_style="bold",
                  show_lines=False, expand=False)
    for _, header in columns:
        table.add_column(header, overflow="fold")
    for row in rows:
        cells = []
        for key, _ in columns:
            # Multi-entry columns stack one value per line to stay aligned; groups read
            # better inline.
            text = _cell(row.get(key), ", " if key == "groups" else "\n")
            cells.append(Text(text, style=STYLE_BY_VALUE.get(text, "")))
        table.add_row(*cells)
    out.print(table)


def render_csv(rows: Sequence[dict], columns: Sequence[Column], stream=None) -> None:
    writer = csv.writer(stream or sys.stdout)
    writer.writerow([key for key, _ in columns])
    for row in rows:
        writer.writerow([csv_safe(_cell(row.get(key), "; ")) for key, _ in columns])


def render_json(data: Any, stream=None) -> None:
    stream = stream or sys.stdout
    json.dump(data, stream, indent=2, default=str, ensure_ascii=False)
    stream.write("\n")


def emit(rows: Sequence[dict], columns: Sequence[Column], fmt: str = "table",
         title: str | None = None, json_data: Any = None) -> None:
    if fmt == "json":
        render_json(json_data if json_data is not None else list(rows))
    elif fmt == "csv":
        render_csv(rows, columns)
    else:
        render_table(rows, columns, title=title)


def kv_table(pairs: Iterable[tuple[str, Any]], title: str | None = None) -> None:
    table = Table(title=sanitize(title) if title else None, show_header=False, box=None)
    table.add_column(style="bold")
    table.add_column(overflow="fold")
    for key, value in pairs:
        text = _cell(value, ", ")
        table.add_row(Text(key), Text(text, style=STYLE_BY_VALUE.get(text, "")))
    console.print(table)


def warn(msg: str) -> None:
    err_console.print(Text("warning: ", style="yellow") + Text(sanitize(msg)))


def error(msg: str) -> None:
    err_console.print(Text("error: ", style="bold red") + Text(sanitize(msg)))
