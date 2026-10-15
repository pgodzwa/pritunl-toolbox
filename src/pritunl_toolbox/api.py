"""Minimal, signed Pritunl REST API client.

Pritunl API auth: every request carries Auth-Token, Auth-Timestamp, Auth-Nonce and
Auth-Signature = base64(HMAC-SHA256(secret, "token&timestamp&nonce&METHOD&path")).
The server rejects re-used nonces and timestamps outside a small window, so every
attempt (including retries) is signed freshly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from typing import Any
from urllib.parse import quote, urlsplit

import requests

from pritunl_toolbox import __version__
from pritunl_toolbox.config import Profile


class PritunlAPIError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class ReadOnlyError(PritunlAPIError):
    pass


def sign_request(token: str, secret: str, method: str, path: str,
                 timestamp: str | None = None, nonce: str | None = None) -> dict[str, str]:
    timestamp = timestamp or str(int(time.time()))
    nonce = nonce or secrets.token_hex(16)
    auth_string = "&".join([token, timestamp, nonce, method.upper(), path])
    digest = hmac.new(secret.encode(), auth_string.encode(), hashlib.sha256).digest()
    return {
        "Auth-Token": token,
        "Auth-Timestamp": timestamp,
        "Auth-Nonce": nonce,
        "Auth-Signature": base64.b64encode(digest).decode(),
    }


def _seg(value: str) -> str:
    """Quote a single path segment so IDs can never alter the request path."""
    return quote(str(value), safe="")


_RETRY_STATUSES = {502, 503, 504}


class PritunlClient:
    def __init__(self, profile: Profile, retries: int = 2):
        self.profile = profile
        self.retries = retries
        self._local = threading.local()
        base = urlsplit(profile.url)
        # Pritunl may be served under a path prefix; the signature covers the full path.
        self._origin = f"{base.scheme}://{base.netloc}"
        self._base_path = base.path.rstrip("/")

    # ------------------------------------------------------------------ transport

    @property
    def session(self) -> requests.Session:
        # requests.Session is not guaranteed thread-safe; keep one per worker thread.
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.headers["User-Agent"] = f"pritunl-toolbox/{__version__}"
            sess.verify = self.profile.ca_bundle or self.profile.verify_tls
            sess.trust_env = True
            self._local.session = sess
        return sess

    def request(self, method: str, path: str, *, params: dict | None = None,
                json_body: Any = None) -> Any:
        method = method.upper()
        if method not in ("GET", "HEAD") and self.profile.read_only:
            raise ReadOnlyError(
                f"profile '{self.profile.name}' is read_only; refusing {method} {path}"
            )
        full_path = self._base_path + path
        url = self._origin + full_path
        attempts = self.retries + 1 if method == "GET" else 1
        last_exc: Exception | None = None
        for attempt in range(attempts):
            headers = sign_request(
                self.profile.api_token, self.profile.api_secret, method, full_path
            )
            if json_body is not None:
                headers["Content-Type"] = "application/json"
            try:
                resp = self.session.request(
                    method, url, params=params, json=json_body, headers=headers,
                    timeout=self.profile.timeout, allow_redirects=False,
                )
            except requests.exceptions.SSLError as exc:
                raise PritunlAPIError(
                    f"TLS verification failed for {self.profile.url}: {exc}. "
                    "Set ca_bundle for a private CA instead of disabling verification."
                ) from exc
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                time.sleep(0.5 * (2 ** attempt))
                continue
            if resp.status_code in _RETRY_STATUSES and attempt + 1 < attempts:
                time.sleep(0.5 * (2 ** attempt))
                continue
            return self._handle(resp, method, path)
        raise PritunlAPIError(f"{method} {path} failed: {last_exc}")

    @staticmethod
    def _handle(resp: requests.Response, method: str, path: str) -> Any:
        if 300 <= resp.status_code < 400:
            # Never follow redirects automatically: auth headers could leak to another host.
            raise PritunlAPIError(
                f"{method} {path}: unexpected redirect to {resp.headers.get('Location')!r}; "
                "check the configured URL", resp.status_code,
            )
        if resp.status_code == 401:
            raise PritunlAPIError(
                "401 Unauthorized: check API token/secret, that the administrator has "
                "'API access' enabled, and that this machine's clock is in sync "
                "(Pritunl rejects timestamps older than a few minutes).", 401,
            )
        if resp.status_code >= 400:
            body = resp.text[:300].replace("\n", " ")
            raise PritunlAPIError(f"{method} {path}: HTTP {resp.status_code}: {body}",
                                  resp.status_code)
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise PritunlAPIError(f"{method} {path}: response is not JSON") from exc

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, params=params or None)

    # ------------------------------------------------------------------ endpoints

    def status(self) -> dict:
        return self.get("/status")

    def organizations(self) -> list[dict]:
        return _unwrap(self.get("/organization"), "organizations")

    def users(self, org_id: str) -> list[dict]:
        return _unwrap(self.get(f"/user/{_seg(org_id)}"), "users")

    def user(self, org_id: str, user_id: str) -> dict:
        return self.get(f"/user/{_seg(org_id)}/{_seg(user_id)}")

    def user_audit(self, org_id: str, user_id: str) -> list[dict]:
        return _unwrap(self.get(f"/audit/{_seg(org_id)}/{_seg(user_id)}"), "audit")

    def set_user_disabled(self, org_id: str, user_id: str, disabled: bool) -> dict:
        return self.request(
            "PUT", f"/user/{_seg(org_id)}/{_seg(user_id)}", json_body={"disabled": disabled}
        )

    def servers(self) -> list[dict]:
        return _unwrap(self.get("/server"), "servers")

    def server(self, server_id: str) -> dict:
        return self.get(f"/server/{_seg(server_id)}")

    def server_orgs(self, server_id: str) -> list[dict]:
        return _unwrap(self.get(f"/server/{_seg(server_id)}/organization"), "organizations")

    def server_routes(self, server_id: str) -> list[dict]:
        return _unwrap(self.get(f"/server/{_seg(server_id)}/route"), "routes")

    def server_hosts(self, server_id: str) -> list[dict]:
        return _unwrap(self.get(f"/server/{_seg(server_id)}/host"), "hosts")

    def server_output(self, server_id: str) -> list[str]:
        data = self.get(f"/server/{_seg(server_id)}/output")
        if isinstance(data, dict):
            return list(data.get("output") or [])
        return list(data or [])

    def hosts(self) -> list[dict]:
        return _unwrap(self.get("/host"), "hosts")


def _unwrap(data: Any, key: str) -> list[dict]:
    """Some endpoints return a list, paged variants return {key: [...]}."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get(key), list):
        return data[key]
    raise PritunlAPIError(f"unexpected response shape (expected list or '{key}')")
