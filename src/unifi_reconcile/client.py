"""HTTP access to the UniFi Network integration API v1.

Two transports, one interface. A console is reached either directly on its
LAN, with a console-local key and usually a self-signed certificate, or through
the Site Manager connector proxy in Ubiquiti's cloud, with a Site Manager key.
Both speak the same /v1 paths below the base URL, which is the whole reason one
tool can drive consoles it cannot reach the same way. `site.yaml` says which.

The connector proxy forwards both integration v1 *and* the legacy
`/proxy/network/api/s/default/...` paths, so the Verified tier works remotely
and not only on the LAN.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.parse

import requests
import urllib3

DEFAULT_TIMEOUT = 30
PAGE_LIMIT = 200


class UniFiError(RuntimeError):
    """An API call failed, or answered something we refuse to act on."""


class VersionMismatch(UniFiError):
    """The console is not running the version site.yaml pins."""


class Client:
    def __init__(self, base_url, api_key, verify_tls=True, timeout=DEFAULT_TIMEOUT):
        # Ubiquiti documents the base URL with /integration/v1 on the end.
        # Paths in this tool
        # carry their own /v1 so they read like the spec. Tolerate both rather
        # than making the documented URL wrong: strip a trailing /v1 here.
        self.base_url = base_url.rstrip("/")
        if self.base_url.endswith("/v1"):
            self.base_url = self.base_url[: -len("/v1")]
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._session = requests.Session()
        self._session.headers.update(
            {"X-API-Key": api_key, "Accept": "application/json"}
        )
        if not verify_tls:
            # A console reached on its LAN address usually presents a
            # self-signed certificate. Suppressing the warning is deliberate
            # and scoped to the site that opted in via verify_tls: false.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ---- construction ----------------------------------------------------

    @classmethod
    def from_site_config(cls, site_cfg, env):
        """Build a client from a site.yaml `console:` block plus the environment.

        Secrets are never in the YAML. The YAML names the environment variable
        that holds the key, which keeps site.yaml committable and makes a
        missing key a clear error rather than a 401.
        """
        console = site_cfg["console"]
        key_var = console["api_key_env"]
        api_key = env.get(key_var)
        if not api_key:
            raise UniFiError(
                f"{key_var} is not set. The default --env-file is "
                "secrets.sops.env in the parent directory of --config; pass "
                "--env-file, or export it."
            )

        base = console["base_url"]
        if "{hostId}" in base:
            host_id = console.get("host_id")
            # A committed placeholder is how a site is written before its
            # console is adopted. Refuse it by name rather than sending it to
            # api.ui.com and reading back an unhelpful 404.
            if not host_id or host_id.startswith("TODO"):
                raise UniFiError(
                    "base_url contains {hostId} but console.host_id is unset "
                    f"({host_id!r}). The hostId exists once the console is "
                    "adopted and Remote Access is on: GET "
                    "https://api.ui.com/v1/hosts with the site's Site Manager "
                    "key, then fill it into site.yaml."
                )
            base = base.replace("{hostId}", host_id)

        return cls(base, api_key, verify_tls=console.get("verify_tls", True))

    # ---- transport -------------------------------------------------------

    def _url(self, path):
        return f"{self.base_url}/{path.lstrip('/')}"

    def _request(self, method, path, absolute=False, **kwargs):
        url = path if absolute else self._url(path)
        try:
            resp = self._session.request(
                method,
                url,
                timeout=self.timeout,
                verify=self.verify_tls,
                **kwargs,
            )
        except requests.exceptions.SSLError as exc:
            raise UniFiError(
                f"TLS failure for {url}. A console reached on its LAN address "
                f"usually presents a self-signed certificate; set "
                f"console.verify_tls: false for that site. ({exc})"
            ) from exc
        except requests.RequestException as exc:
            raise UniFiError(f"{method} {url} failed: {exc}") from exc

        if resp.status_code == 401:
            raise UniFiError(
                f"401 from {url}. The API key is wrong, revoked, or belongs to "
                "a different console."
            )
        if not resp.ok:
            raise UniFiError(
                f"{method} {url} -> {resp.status_code}: {_short(resp.text)}"
            )
        if not resp.content:
            return None
        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            # A console that returns the UniFi OS SPA shell instead of JSON
            # means the path is wrong -- /unifi-api/... does this.
            raise UniFiError(
                f"{method} {url} returned non-JSON ({_short(resp.text)})"
            ) from exc

    def get(self, path, params=None):
        return self._request("GET", path, params=params)

    def post(self, path, body, params=None):
        return self._request("POST", path, json=body, params=params)

    def put(self, path, body, params=None):
        return self._request("PUT", path, json=body, params=params)

    def patch(self, path, body, params=None):
        return self._request("PATCH", path, json=body, params=params)

    def delete(self, path, params=None):
        return self._request("DELETE", path, params=params)

    def get_all(self, path, params=None):
        """GET a paged collection and return every item.

        The API caps `limit`, so a site with more policies than one page holds
        would silently truncate without this. 126 policies already exceeds the
        default page of 25.
        """
        params = dict(params or {})
        params.setdefault("limit", PAGE_LIMIT)
        offset, items = 0, []
        while True:
            params["offset"] = offset
            page = self.get(path, params=params)
            if page is None:
                return items
            if "data" not in page:
                # A detail endpoint, not a collection.
                return page
            items.extend(page["data"])
            total = page.get("totalCount")
            if total is None or len(items) >= total or not page["data"]:
                return items
            offset = len(items)

    # ---- legacy API (Verified tier, read-only) ---------------------------

    def legacy_get(self, path, site="default"):
        """GET a legacy controller path and return its `data` list.

        The legacy API lives beside the integration API under the same
        /proxy/network prefix -- `.../proxy/network/api/s/<site>/...` rather
        than `.../proxy/network/integration/v1/...` -- and takes the same key,
        locally and through the connector proxy alike. It is the only place the
        Verified tier's settings can be read at all (reservations, radios,
        port overrides, WAN DNS, Auto-Link).

        There is deliberately no legacy write method. Legacy writes are
        full-record replaces with no schema, and the records carry credentials;
        the Verified tier reads and reports, and the UI stays the write path.
        """
        if not self.base_url.endswith("/integration"):
            raise UniFiError(
                f"cannot derive the legacy API from base_url {self.base_url!r}; "
                "expected it to end in /proxy/network/integration[/v1]"
            )
        root = self.base_url[: -len("/integration")]
        body = self._request("GET", f"{root}/api/s/{quote(site)}/{path.lstrip('/')}",
                             absolute=True)
        meta = (body or {}).get("meta", {})
        if meta.get("rc") != "ok":
            raise UniFiError(f"legacy GET {path} answered rc={meta.get('rc')!r} "
                             f"({meta.get('msg')})")
        return body.get("data", [])

    # ---- console identity ------------------------------------------------

    def application_version(self):
        info = self.get("/v1/info") or {}
        version = info.get("applicationVersion")
        if not version:
            raise UniFiError(f"GET /v1/info returned no applicationVersion: {info}")
        return version

    def assert_version(self, pinned, allow_mismatch=False):
        """Compare the live version to site.yaml's pin.

        The published OpenAPI spec is not
        versioned per release, so the console's own reported version is the
        only thing that says whether the behavior this tool was written against
        still holds.
        """
        actual = self.application_version()
        if actual == pinned:
            return actual
        message = (
            f"Console runs Network {actual}; site.yaml pins {pinned}. "
            "Follow 'When a console's version changes' in api-hazards.md "
            "(https://github.com/elklabs-net/unifi-reconcile/blob/main/"
            "api-hazards.md), then move the pin."
        )
        if allow_mismatch:
            return actual
        raise VersionMismatch(message)

    def resolve_site_id(self, internal_reference="default"):
        """Map a stable site reference to the per-console site UUID.

        site.yaml names `default`, not a UUID, for the same reason the rest of
        the YAML names objects rather than UUIDs: the UUID differs per console,
        and naming it would make otherwise identical sites' files differ.
        """
        sites = self.get_all("/v1/sites")
        for site in sites:
            if site.get("internalReference") == internal_reference:
                return site["id"]
        found = ", ".join(
            f"{s.get('internalReference')} ({s.get('name')})" for s in sites
        )
        raise UniFiError(
            f"No site with internalReference '{internal_reference}'. Found: {found}"
        )


def _short(text, limit=300):
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit] + "..."


def _sops_env():
    """The environment for `sops decrypt`, with SOPS_AGE_KEY_FILE defaulted.

    sops reads age keys from its user config directory, which is ~/.config on
    Linux but ~/Library/Application Support on macOS. Keys kept at the Linux
    path on a Mac are found only when SOPS_AGE_KEY_FILE says so, and a shell
    that never read the user's profile does not have it. When the variable is
    unset or empty and ~/.config/sops/age/keys.txt exists, point sops there.
    An explicit setting always wins.
    """
    env = dict(os.environ)
    key_file = os.path.expanduser("~/.config/sops/age/keys.txt")
    if not env.get("SOPS_AGE_KEY_FILE") and os.path.isfile(key_file):
        env["SOPS_AGE_KEY_FILE"] = key_file
    return env


def load_env_file(path):
    """Read a KEY=VALUE file over the environment, without python-dotenv.

    A *.sops.* file is decrypted in memory with `sops decrypt`, so the key never
    touches disk; any other path is read as plaintext (--env-file overrides).
    A missing file leaves the process environment as the only source.
    """
    env = dict(os.environ)
    if not path or not os.path.exists(path):
        return env
    if ".sops." in os.path.basename(path):
        result = subprocess.run(
            ["sops", "decrypt", path], capture_output=True, text=True, env=_sops_env()
        )
        if result.returncode != 0:
            raise SystemExit(
                f"sops could not decrypt {path} (is SOPS_AGE_KEY_FILE set?):\n{result.stderr}"
            )
        text = result.stdout
    else:
        with open(path) as handle:
            text = handle.read()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def quote(value):
    return urllib.parse.quote(str(value), safe="")
