"""Live search-layer tests (paged search, low-level search, tree plot)."""
import pytest

from support.agen import collect, first

pytestmark = [pytest.mark.live, pytest.mark.asyncio]


async def test_pagedsearch_returns_entries(client):
    entries = await collect(
        client.pagedsearch("(objectClass=*)", ["distinguishedName"]), limit=5
    )
    assert len(entries) >= 1
    assert "attributes" in entries[0]


async def test_pagedsearch_specific_attribute(client):
    entry = await first(
        client.pagedsearch("(objectClass=domain)", ["objectSid", "distinguishedName"])
    )
    assert entry is not None
    assert entry["attributes"].get("objectSid")


async def test_low_level_search(connection, client):
    tree = client._tree
    results = await collect(
        connection.pagedsearch(tree, "(objectClass=*)", [b"distinguishedName"]),
        limit=5,
    )
    assert len(results) >= 1


async def test_get_childobjects(client):
    kids = await collect(client.get_childobjects(client._tree), limit=5)
    assert isinstance(kids, list)


async def test_get_tree_plot(client):
    tree = await client.get_tree_plot(client._tree, level=1)
    assert isinstance(tree, dict)
    assert client._tree in tree


async def test_dnattrs(client):
    # resolve the domain object's own attributes by DN
    attrs, err = await client.dnattrs(client._tree, ["objectSid", "distinguishedName"])
    assert err is None, err
    assert attrs is not None
    assert attrs.get("objectSid")
