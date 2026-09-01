"""Fixtures for the live/interop msldap tests.

All fixtures here are gated behind ``--run-live`` (enforced both by the root
conftest's collection policy and defensively here). If the configured target is
not reachable the whole live module is skipped with a clear message rather than
erroring out.
"""
import pytest
import pytest_asyncio

from _lab import (
    load_profile,
    is_reachable,
    logged_in_client,
    raw_connection,
    ProfileError,
)


@pytest.fixture(scope="session")
def live_profile(request):
    if not (request.config.getoption("--run-live") or request.config.getoption("--run-destructive")):
        pytest.skip("requires --run-live opt-in")
    try:
        profile = load_profile()
    except ProfileError as e:
        pytest.skip("interop profile unavailable: %s" % e)
    if not profile.disposable:
        pytest.skip("target is not declared disposable (safety.disposable: true)")
    if not is_reachable(profile):
        pytest.skip(
            "live target %s:%d is not reachable" % (profile.host, profile.resolved_port)
        )
    return profile


@pytest.fixture(scope="session")
def destructive_profile(request, live_profile):
    if not request.config.getoption("--run-destructive"):
        pytest.skip("requires --run-destructive opt-in")
    if not live_profile.allow_destructive:
        pytest.skip("profile does not allow destructive tests (safety.allow_destructive: true)")
    return live_profile


@pytest_asyncio.fixture
async def client(live_profile):
    """A connected + bound MSLDAPClient for the session's target."""
    async with logged_in_client(live_profile) as c:
        yield c


@pytest_asyncio.fixture
async def connection(live_profile):
    """A connected + bound low-level MSLDAPClientConnection."""
    async with raw_connection(live_profile) as c:
        yield c


# --- alternate targets in the same lab -------------------------------------
# These let tests reach the forest root (ADCS/CA config), the other forest
# (cross-forest trust/SID resolution) and the Global Catalog. Each fixture
# skips cleanly when the corresponding target is not configured/reachable.

def _variant_profile(live_profile, name):
    variant = live_profile.variant_for(name)
    if variant is None:
        pytest.skip("extra_targets['%s'] not configured in the profile" % name)
    if not is_reachable(variant):
        pytest.skip(
            "extra target '%s' (%s:%d) not reachable"
            % (name, variant.host, variant.resolved_port)
        )
    return variant


@pytest.fixture(scope="session")
def root_profile(live_profile):
    """Profile for the forest-root DC (ADCS/Configuration partition live here)."""
    return _variant_profile(live_profile, "root")


@pytest.fixture(scope="session")
def essos_profile(live_profile):
    """Profile for the second forest (trust partner)."""
    return _variant_profile(live_profile, "essos")


@pytest_asyncio.fixture
async def root_client(root_profile):
    async with logged_in_client(root_profile) as c:
        yield c


@pytest_asyncio.fixture
async def essos_client(essos_profile):
    async with logged_in_client(essos_profile) as c:
        yield c


@pytest_asyncio.fixture
async def gc_client(live_profile):
    """A client bound to the Global Catalog (forest-wide, read-only) port."""
    gc = live_profile.gc_variant()
    if not is_reachable(gc):
        pytest.skip("Global Catalog %s:%d not reachable" % (gc.host, gc.resolved_port))
    async with logged_in_client(gc) as c:
        yield c
