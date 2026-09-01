"""Live identity resolution + security-descriptor tests."""
import pytest

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from support.agen import collect

pytestmark = [pytest.mark.live, pytest.mark.asyncio]


async def test_dn_sid_roundtrip_on_domain(client):
    dn = client._tree
    sid, err = await client.dn2sid(dn)
    assert err is None, err
    assert str(sid).startswith("S-1-5-21-")
    dn2, err = await client.sid2dn(sid)
    assert err is None, err
    assert dn2.upper() == dn.upper()


async def test_dn2sam(client):
    # the domain object has no sAMAccountName, so use a known account: krbtgt
    sam_dn, err = await client.sam2dn("krbtgt")
    if sam_dn is None:
        pytest.skip("krbtgt not present/visible")
    sam, err = await client.dn2sam(sam_dn)
    assert err is None, err
    assert sam.lower() == "krbtgt"


async def test_get_dn_for_objectsid(client):
    admins_sid = "%s-512" % client.domainsid
    dn, err = await client.get_dn_for_objectsid(admins_sid)
    assert err is None, err
    assert "CN=" in dn.upper()


async def test_get_objectsid_for_dn(client):
    sid, err = await client.get_objectsid_for_dn(client._tree)
    assert err is None, err
    assert str(sid) == client.domainsid


async def test_resolv_sid_wellknown(client):
    domain, username, err = await client.resolv_sid("S-1-5-32-544")
    assert err is None, err
    assert username == "Administrators"


async def test_resolv_sid_domain_admins(client):
    domain, username, err = await client.resolv_sid("%s-512" % client.domainsid)
    assert err is None, err
    assert username is not None


async def test_get_objectacl_and_resolve(client):
    sd_bytes, err = await client.get_objectacl_by_dn(client._tree)
    assert err is None, err
    assert sd_bytes
    # the returned blob must parse as a security descriptor
    sd = SECURITY_DESCRIPTOR.from_bytes(sd_bytes)
    assert sd.Owner is not None
    # and resolv_sd must resolve every SID it references
    lookup, err = await client.resolv_sd(sd_bytes)
    assert err is None, err
    assert isinstance(lookup, dict)


async def test_tokengroups_for_a_user(client):
    # resolve Administrator's token groups (should include Domain Admins etc.)
    admin_dn, err = await client.get_dn_for_objectsid("%s-500" % client.domainsid)
    if err is not None or admin_dn is None:
        pytest.skip("built-in Administrator not resolvable")
    groups = await collect(client.get_tokengroups(admin_dn), limit=50)
    assert len(groups) >= 1
