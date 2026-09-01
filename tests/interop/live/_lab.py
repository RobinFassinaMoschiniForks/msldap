"""Live-target lab profile handling for msldap interop tests.

Nothing here opens a connection at import time. Profiles are loaded from a YAML
file; secrets may be supplied inline (lab-only) or, preferably, via environment
variables so that no real credential is committed.

Resolution order for the profile path:
    1. ``$MSLDAP_TEST_PROFILE``
    2. ``tests/interop/live/profile.local.yml``   (git-ignored, your real lab)
    3. ``tests/interop/live/profile.example.yml``  (committed, safe defaults)
"""
import os
import socket
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from typing import Optional
from urllib.parse import quote

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from msldap.commons.factory import LDAPConnectionFactory

_HERE = os.path.dirname(__file__)
_DEFAULT_PROFILES = (
    os.environ.get("MSLDAP_TEST_PROFILE"),
    os.path.join(_HERE, "profile.local.yml"),
    os.path.join(_HERE, "profile.example.yml"),
)

_DEFAULT_PORTS = {
    "ldap": 389,
    "ldaps": 636,
    "gc": 3268,
    "gc-ssl": 3269,
}


class ProfileError(RuntimeError):
    pass


@dataclass
class LabProfile:
    host: str
    protocol: str = "ldap"
    port: Optional[int] = None
    dc_ip: Optional[str] = None
    tree: Optional[str] = None
    auth_method: str = "ntlm-password"
    domain: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    disposable: bool = False
    allow_destructive: bool = False
    extra_params: dict = field(default_factory=dict)
    # named alternate targets in the same lab, e.g. {"root": {...}, "essos": {...}}
    extra_targets: dict = field(default_factory=dict)

    @property
    def resolved_port(self) -> int:
        if self.port:
            return self.port
        return _DEFAULT_PORTS.get(self.protocol, 389)

    def url(self, auth_method: Optional[str] = None) -> str:
        """Build an msldap connection URL from the profile components."""
        method = auth_method or self.auth_method
        scheme = self.protocol
        if method and method != "anonymous":
            scheme = "%s+%s" % (self.protocol, method)

        userinfo = ""
        if self.username is not None and method not in (None, "anonymous"):
            user = self.username
            if self.domain:
                user = "%s\\%s" % (self.domain, self.username)
            userinfo = quote(user, safe="\\")
            if self.password is not None:
                userinfo += ":" + quote(self.password, safe="")
            userinfo += "@"

        netloc = "%s:%d" % (self.host, self.resolved_port)
        path = ""
        if self.tree:
            path = "/" + self.tree.strip("/") + "/"

        params = dict(self.extra_params)
        if self.dc_ip:
            params.setdefault("dc", self.dc_ip)
        query = ""
        if params:
            query = "/?" + "&".join("%s=%s" % (k, v) for k, v in params.items())
            if path:
                # move params after the tree path
                query = "?" + "&".join("%s=%s" % (k, v) for k, v in params.items())

        return "%s://%s%s%s%s" % (scheme, userinfo, netloc, path, query)

    def factory(self, auth_method: Optional[str] = None) -> LDAPConnectionFactory:
        return LDAPConnectionFactory.from_url(self.url(auth_method))

    def derive(self, **overrides) -> "LabProfile":
        """Return a copy of this profile with selected fields overridden.

        Credentials/safety flags are inherited unless explicitly overridden, so
        alternate targets in the same lab reuse the same account by default.
        """
        return replace(self, **overrides)

    def variant_for(self, name: str) -> Optional["LabProfile"]:
        """Build a LabProfile for a named entry under ``extra_targets``.

        Returns ``None`` when the named target is not configured, letting the
        caller skip cleanly.
        """
        spec = (self.extra_targets or {}).get(name)
        if not spec:
            return None
        host = spec.get("host", self.host)
        return self.derive(
            host=host,
            protocol=spec.get("protocol", self.protocol),
            port=spec.get("port"),
            dc_ip=spec.get("dc_ip") or host,
            tree=spec.get("tree"),
            domain=spec.get("domain", self.domain),
            username=spec.get("username", self.username),
            password=spec.get("password", self.password),
            auth_method=spec.get("method", self.auth_method),
            extra_targets={},
        )

    def gc_variant(self) -> "LabProfile":
        """A Global-Catalog variant of this profile (port 3268/3269)."""
        proto = "gc-ssl" if self.protocol in ("ldaps", "gc-ssl") else "gc"
        return self.derive(protocol=proto, port=None, tree=None)


def _env_or_value(cfg: dict, key: str) -> Optional[str]:
    """Return cfg[key], or the value of the env var named cfg[key + '_env']."""
    env_key = cfg.get(key + "_env")
    if env_key and os.environ.get(env_key) is not None:
        return os.environ[env_key]
    return cfg.get(key)


def _profile_path() -> Optional[str]:
    for candidate in _DEFAULT_PROFILES:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def load_profile() -> LabProfile:
    if yaml is None:
        raise ProfileError("PyYAML is required for interop tests (pip install pyyaml)")
    path = _profile_path()
    if path is None:
        raise ProfileError("No interop profile found (see tests/interop/live/profile.example.yml)")
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    target = cfg.get("target", {})
    auth = cfg.get("authentication", {})
    safety = cfg.get("safety", {})

    host = os.environ.get("MSLDAP_TEST_HOST") or target.get("host")
    if not host:
        raise ProfileError("Profile is missing target.host")

    return LabProfile(
        host=host,
        protocol=target.get("protocol", "ldap"),
        port=target.get("port"),
        dc_ip=target.get("dc_ip") or host,
        tree=cfg.get("tree"),
        auth_method=auth.get("method", "ntlm-password"),
        domain=_env_or_value(auth, "domain"),
        username=_env_or_value(auth, "username"),
        password=_env_or_value(auth, "password"),
        disposable=bool(safety.get("disposable", False)),
        allow_destructive=bool(safety.get("allow_destructive", False)),
        extra_params=cfg.get("params", {}) or {},
        extra_targets=cfg.get("extra_targets", {}) or {},
    )


def is_reachable(profile: LabProfile, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((profile.host, profile.resolved_port), timeout=timeout):
            return True
    except OSError:
        return False


@asynccontextmanager
async def logged_in_client(profile: LabProfile, auth_method: Optional[str] = None):
    """Yield a connected+bound MSLDAPClient, tearing it down afterwards."""
    client = profile.factory(auth_method).get_client()
    _, err = await client.connect()
    if err is not None:
        raise err
    try:
        yield client
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


@asynccontextmanager
async def raw_connection(profile: LabProfile, auth_method: Optional[str] = None):
    """Yield a connected+bound low-level MSLDAPClientConnection."""
    conn = profile.factory(auth_method).get_connection()
    _, err = await conn.connect()
    if err is not None:
        raise err
    _, err = await conn.bind()
    if err is not None:
        await conn.disconnect()
        raise err
    try:
        yield conn
    finally:
        try:
            await conn.disconnect()
        except Exception:
            pass
