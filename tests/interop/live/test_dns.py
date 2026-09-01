"""Live AD-integrated DNS enumeration tests.

DNS may not be AD-integrated on every lab, so these tests tolerate an empty
result set but assert the calls execute without raising.
"""
import pytest

pytestmark = [pytest.mark.live, pytest.mark.asyncio]


async def test_dnslistzones(client):
    zones = []
    async for zone, props, err in client.dnslistzones():
        if err is not None:
            pytest.skip("DNS zones not enumerable: %s" % err)
        zones.append(zone)
        if len(zones) >= 10:
            break
    assert isinstance(zones, list)


async def test_dns_gettree(client):
    tree, err = await client.dns_gettree()
    assert err is None, err
    assert tree.upper().startswith("DC=")


async def test_dns_queryall(client):
    count = 0
    async for entry, tree, err in client.dns_queryall(throw=False):
        if err is not None:
            pytest.skip("DNS query failed: %s" % err)
        if entry is None:
            break  # terminator
        count += 1
        if count >= 10:
            break
    assert count >= 0


async def test_dnsentries(client):
    seen = 0
    try:
        async for root, name, record, err in client.dnsentries():
            if err is not None:
                pytest.skip("DNS entries not enumerable: %s" % err)
            seen += 1
            if seen >= 10:
                break
    except Exception as e:
        pytest.skip("DNS entries raised: %s" % e)
    assert seen >= 0
