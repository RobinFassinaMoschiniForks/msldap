"""Live forest-wide tests: Global Catalog, trusts, gMSA and cross-forest SIDs.

Uses the whole GOAD lab:
  * ``root_client``  -> forest root (sevenkingdoms.local)
  * ``essos_client`` -> the trusted second forest (essos.local)
  * ``gc_client``    -> the Global Catalog (forest-wide partial replica)
Each fixture skips cleanly when its target is not configured/reachable.
"""
import pytest

from support.agen import collect
from msldap.ldap_objects.adtrust import MSADDomainTrust
from msldap.ldap_objects.adgmsa import MSADGMSAUser

pytestmark = [pytest.mark.live, pytest.mark.asyncio]


async def test_root_sees_trusts(root_client):
    trusts = await collect(root_client.get_all_trusts(), limit=20)
    assert trusts, "forest root should have at least one trustedDomain"
    for t in trusts:
        assert isinstance(t, MSADDomainTrust)
        assert t.name
        assert isinstance(t.to_dict(), dict)
    names = {(t.name or "").lower() for t in trusts}
    # GOAD: sevenkingdoms trusts its child (north) and the essos forest
    assert any("essos" in n or "north" in n for n in names)


async def test_essos_trusts_back(essos_client):
    trusts = await collect(essos_client.get_all_trusts(), limit=20)
    names = {(t.name or "").lower() for t in trusts}
    assert any("sevenkingdoms" in n for n in names), (
        "essos should trust sevenkingdoms, got %r" % names
    )


async def test_global_catalog_is_forest_wide(gc_client):
    # The GC holds partial replicas of *every* domain in the forest. Searching
    # from an empty base DN (only valid on the GC) crosses domain boundaries, so
    # we should see more than just the connected domain's head.
    heads = await collect(
        gc_client.pagedsearch("(objectClass=domainDNS)", ["distinguishedName"], tree=""),
        limit=50,
    )
    dns = {e["attributes"].get("distinguishedName") for e in heads}
    dns.discard(None)
    assert dns, "GC returned no domain heads"
    # at least sevenkingdoms + north live in this forest
    assert len(dns) >= 2, "expected multiple domains in the GC, got %r" % dns


async def test_gc_search_users_forest_wide(gc_client):
    users = await collect(
        gc_client.pagedsearch("(objectClass=user)", ["sAMAccountName"], tree=""),
        limit=50,
    )
    assert isinstance(users, list)
    assert users, "GC should return users from across the forest"


async def test_essos_gmsa(essos_client):
    gmsas = await collect(essos_client.get_all_gmsa(), limit=20)
    if not gmsas:
        pytest.skip("no gMSA deployed in essos")
    for g in gmsas:
        assert isinstance(g, MSADGMSAUser)
        assert g.sAMAccountName
        assert isinstance(g.to_dict(), dict)


async def test_cross_domain_sid_resolution_in_forest(root_client):
    # Resolve the root domain's own SID, then a couple of well-known RIDs.
    domainsid = root_client.domainsid
    assert domainsid
    for rid in ("512", "500"):  # Domain Admins, Administrator
        domain, username, err = await root_client.resolv_sid("%s-%s" % (domainsid, rid))
        assert err is None, err
        assert domain and domain != "???"
        assert username
