"""Live enumeration of core AD object types."""
import pytest

from msldap.ldap_objects.aduser import MSADUser
from msldap.ldap_objects.adcomp import MSADMachine
from msldap.ldap_objects.adgroup import MSADGroup
from support.agen import collect, first

pytestmark = [pytest.mark.live, pytest.mark.asyncio]


async def test_get_all_users(client):
    users = await collect(client.get_all_users(), limit=10)
    assert len(users) >= 1
    assert all(isinstance(u, MSADUser) for u in users)
    assert all(u.sAMAccountName for u in users)


async def test_get_all_machines(client):
    machines = await collect(client.get_all_machines(), limit=10)
    # a domain always has at least the DC computer object
    assert len(machines) >= 1
    assert all(isinstance(m, MSADMachine) for m in machines)


async def test_get_all_groups(client):
    groups = await collect(client.get_all_groups(), limit=10)
    assert len(groups) >= 1
    assert all(isinstance(g, MSADGroup) for g in groups)


async def test_get_all_ous(client):
    ous = await collect(client.get_all_ous(), limit=10)
    assert isinstance(ous, list)


async def test_get_all_gpos(client):
    gpos = await collect(client.get_all_gpos(), limit=10)
    assert isinstance(gpos, list)


async def test_get_all_containers(client):
    containers = await collect(client.get_all_containers(), limit=10)
    assert isinstance(containers, list)


async def test_get_all_domain_controllers(client):
    dcs = await collect(client.get_all_domain_controllers(), limit=10)
    assert len(dcs) >= 1


async def test_get_all_trusts(client):
    trusts = await collect(client.get_all_trusts(), limit=10)
    assert isinstance(trusts, list)


async def test_get_user_roundtrip(client):
    # pick an arbitrary user then re-fetch it by name
    sample = await first(client.get_all_users())
    assert sample is not None
    fetched, err = await client.get_user(sample.sAMAccountName)
    assert err is None, err
    assert fetched is not None
    assert fetched.sAMAccountName == sample.sAMAccountName


async def test_get_machine_roundtrip(client):
    sample = await first(client.get_all_machines())
    assert sample is not None
    fetched, err = await client.get_machine(sample.sAMAccountName)
    assert err is None, err
    assert fetched is not None


async def test_get_user_by_dn(client):
    sample = await first(client.get_all_users())
    user, err = await client.get_user_by_dn(sample.distinguishedName)
    assert err is None, err
    assert user is not None


async def test_get_group_members_of_domain_admins(client):
    # Domain Admins always exists; resolve by DN then list members
    da_dn, err = await client.sid2dn("%s-512" % client.domainsid)
    assert err is None, err
    if da_dn is None:
        pytest.skip("Domain Admins group not resolvable on this target")
    members = await collect(client.get_group_members(da_dn), limit=20)
    assert isinstance(members, list)
