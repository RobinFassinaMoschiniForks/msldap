"""Fixtures for the OpenLDAP (non-AD) interop tests.

These exercise the parts of msldap that used to assume an Active Directory
server on the other end (base-DN discovery from the RootDSE, paged search,
simple bind against a DN). They run against a disposable OpenLDAP container:

    docker compose -f tests/interop/openldap/docker-compose.yml up -d
    pytest tests/interop/openldap --run-live

Everything here is gated behind ``--run-live`` and skips cleanly (never errors)
when the server is not reachable, matching the rest of the suite.
"""
import os
import socket
from contextlib import asynccontextmanager
from urllib.parse import quote, urlparse

import pytest
import pytest_asyncio

from msldap.commons.factory import LDAPConnectionFactory

# Defaults match tests/interop/openldap/docker-compose.yml.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 3389
BASE_DN = "dc=example,dc=org"
ADMIN_DN = "cn=admin,dc=example,dc=org"
ADMIN_PW = "admin123"

# DNs that the seed data (seed.ldif) guarantees to exist under the base DN.
SEEDED_DNS = {
    "dc=example,dc=org",
    "ou=people,dc=example,dc=org",
    "ou=groups,dc=example,dc=org",
    "uid=alice,ou=people,dc=example,dc=org",
    "uid=bob,ou=people,dc=example,dc=org",
    "uid=carol,ou=people,dc=example,dc=org",
    "cn=admins,ou=groups,dc=example,dc=org",
}


def openldap_url() -> str:
    """msldap connection URL for the OpenLDAP target.

    Override wholesale with ``$MSLDAP_OPENLDAP_URL`` (e.g. to point at ldaps or
    a different host); otherwise build a simple-bind URL from the defaults.
    """
    override = os.environ.get("MSLDAP_OPENLDAP_URL")
    if override:
        return override
    host = os.environ.get("MSLDAP_OPENLDAP_HOST", DEFAULT_HOST)
    port = int(os.environ.get("MSLDAP_OPENLDAP_PORT", DEFAULT_PORT))
    return "ldap+simple://%s:%s@%s:%d/%s/" % (
        quote(ADMIN_DN, safe=""),
        quote(ADMIN_PW, safe=""),
        host,
        port,
        quote(BASE_DN, safe="=,"),
    )


def _host_port(url: str):
    p = urlparse(url)
    port = p.port or (636 if p.scheme.split("+")[0] in ("ldaps", "ldap-ssl") else 389)
    return p.hostname or DEFAULT_HOST, port


def _reachable(url: str, timeout: float = 3.0) -> bool:
    host, port = _host_port(url)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def openldap_target(request):
    if not (request.config.getoption("--run-live") or request.config.getoption("--run-destructive")):
        pytest.skip("requires --run-live opt-in")
    url = openldap_url()
    if not _reachable(url):
        host, port = _host_port(url)
        pytest.skip(
            "OpenLDAP not reachable at %s:%d "
            "(start it with: docker compose -f tests/interop/openldap/docker-compose.yml up -d)"
            % (host, port)
        )
    return url


@asynccontextmanager
async def _connected_client(url: str):
    client = LDAPConnectionFactory.from_url(url).get_client()
    ok, err = await client.connect()
    if err is not None:
        raise err
    assert ok is True
    try:
        yield client
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


@pytest_asyncio.fixture
async def openldap_client(openldap_target):
    """A connected + bound high-level MSLDAPClient against OpenLDAP."""
    async with _connected_client(openldap_target) as c:
        yield c
