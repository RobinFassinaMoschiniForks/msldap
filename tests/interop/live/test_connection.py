"""Live connection / bind / RootDSE tests."""
import pytest

from _lab import logged_in_client

pytestmark = [pytest.mark.live, pytest.mark.asyncio]


async def test_factory_test_connection(live_profile):
    ok, ntlm_data, err = await live_profile.factory().test_connection()
    assert err is None, err
    assert ok is True


async def test_connect_and_bind(client):
    # fixture already connected+bound; presence of server info proves the bind
    assert client.get_server_info() is not None


async def test_rootdse_has_naming_contexts(client):
    info = client.get_server_info()
    assert "defaultNamingContext" in info
    assert info["defaultNamingContext"]


async def test_tree_autodetected(client):
    assert client._tree
    assert client._tree.upper().startswith("DC=")


async def test_ad_info(client):
    info, err = await client.get_ad_info()
    assert err is None, err
    assert info is not None
    assert str(info.objectSid).startswith("S-1-5-21-")


async def test_domain_name(client):
    name, err = await client.get_domain_name()
    assert err is None, err
    assert "." in name


async def test_whoami(client):
    res, err = await client.whoami()
    # some servers/configs disable the whoami extended op; tolerate that but the
    # call itself must not raise
    if err is None:
        assert isinstance(res, str)


async def test_low_level_connection_serverinfo(connection):
    info, err = await connection.get_serverinfo()
    assert err is None, err
    assert "defaultNamingContext" in info


async def test_second_client_newtarget_same_host(live_profile):
    # exercise the newtarget code path against the same reachable host
    fact = live_profile.factory()
    client = fact.get_client_newtarget(live_profile.host)
    ok, err = await client.connect()
    try:
        assert err is None, err
        assert ok is True
    finally:
        await client.disconnect()
