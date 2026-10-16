# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 pritunl-toolbox contributors
"""Pritunl toolbox - read-only CLI and terminal UI for Pritunl VPN servers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("pritunl-toolbox")  # set from the git tag at build time
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0.0.0+unknown"

LICENSE_NOTICE = (
    "License GPL-3.0-or-later <https://www.gnu.org/licenses/gpl-3.0.html>.\n"
    "This is free software: you are free to change and redistribute it.\n"
    "There is NO WARRANTY, to the extent permitted by law."
)
