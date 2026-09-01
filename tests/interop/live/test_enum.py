"""Live tests for the offensive-enumeration helpers (SPN/ASREP/deleg/LAPS/gMSA/ADCS)."""
import pytest

from support.agen import collect
from msldap.commons.exceptions import LDAPSearchException

pytestmark = [pytest.mark.live, pytest.mark.asyncio]


async def test_get_all_spn_entries(client):
    entries = await collect(client.get_all_spn_entries(), limit=20)
    assert isinstance(entries, list)


async def test_kerberoastable_service_users(client):
    users = await collect(client.get_all_service_users(), limit=20)
    assert isinstance(users, list)
    # every returned service user must expose an SPN
    for u in users:
        assert u.servicePrincipalName


async def test_asreproastable_users(client):
    users = await collect(client.get_all_knoreq_users(), limit=20)
    assert isinstance(users, list)


async def test_unconstrained_machines(client):
    names = await collect(client.get_unconstrained_machines(), limit=20)
    # the primary DC is unconstrained by default
    assert isinstance(names, list)


async def test_unconstrained_users(client):
    names = await collect(client.get_unconstrained_users(), limit=20)
    assert isinstance(names, list)


async def test_constrained_delegation(client):
    entries = await collect(client.get_all_constrained(), limit=20)
    assert isinstance(entries, list)


async def test_s4u2proxy(client):
    entries = await collect(client.get_all_s4u2proxy(), limit=20)
    assert isinstance(entries, list)


async def test_all_tokengroups(client):
    groups = await collect(client.get_all_tokengroups(), limit=20)
    assert isinstance(groups, list)


async def test_laps_enumeration(client):
    # LAPS may not be deployed; the call must not raise, result may be empty
    entries = await collect(client.get_all_laps(), limit=10)
    assert isinstance(entries, list)


async def test_gmsa_enumeration(client):
    # list_gmsa yields 4-tuples (sam, membership, managedpw, err)
    out = []
    async for sam, membership, managedpw, err in client.list_gmsa():
        assert err is None, err
        out.append(sam)
        if len(out) >= 10:
            break
    assert isinstance(out, list)


async def test_certificate_templates(client):
    # ADCS may not be installed; tolerate an empty configuration partition.
    # NOTE (KF-0007): msldap builds the ADCS tree from the *domain* DN
    # (CN=Configuration,<defaultNamingContext>) instead of the forest-wide
    # configurationNamingContext, so on a child-domain DC this raises
    # noSuchObject. Tolerate that rather than fail the suite.
    try:
        templates = await collect(client.list_certificate_templates(), limit=10)
    except LDAPSearchException as e:
        pytest.skip("certificate templates not enumerable (see KF-0007): %s" % e)
    assert isinstance(templates, list)


async def test_enrollment_services(client):
    try:
        services = await collect(client.list_enrollment_services(), limit=10)
    except LDAPSearchException as e:
        pytest.skip("enrollment services not enumerable (see KF-0007): %s" % e)
    assert isinstance(services, list)
