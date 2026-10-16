"""Pritunl toolbox - read-only CLI and terminal UI for Pritunl VPN servers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("pritunl-toolbox")  # set from the git tag at build time
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0.0.0+unknown"
