"""Destructive live tests: create / modify / delete directory objects.

Gated behind BOTH ``--run-destructive`` and ``safety.allow_destructive: true``.
Only ever point these at a disposable lab. Every test cleans up after itself.

Password-write operations (add_computer, create_user_dn) require a confidential
channel (LDAPS or LDAP+sign/seal). When the target rejects them on the current
channel the test skips rather than fails.
"""
import random
import string

import pytest

from support.agen import collect

pytestmark = [pytest.mark.live, pytest.mark.destructive, pytest.mark.asyncio]


def _rand(prefix):
    return prefix + "".join(random.choice(string.ascii_lowercase) for _ in range(8))


def _is_confidentiality_error(err) -> bool:
    text = str(err).lower()
    return any(
        marker in text
        for marker in ("confidential", "unwilling", "strongerauth", "0x2028", "8232")
    )


@pytest.fixture
def users_container(client):
    return "CN=Users,%s" % client._tree


async def test_create_modify_delete_group(destructive_profile, client, users_container):
    name = _rand("msldaptest_grp_")
    dn = "CN=%s,%s" % (name, users_container)
    attributes = {
        "objectClass": ["top", "group"],
        "sAMAccountName": name,
        "groupType": 0x80000002,  # global security group
        "description": "created by msldap test suite",
    }
    ok, err = await client.add(dn, attributes)
    assert err is None, err
    assert ok
    try:
        # modify the description
        _, err = await client.modify(dn, {"description": [("replace", "modified")]})
        assert err is None, err
        attrs, err = await client.dnattrs(dn, ["description"])
        assert err is None, err
        assert attrs["description"] == "modified"
    finally:
        ok, err = await client.delete(dn)
        assert err is None, err


async def test_group_membership_add_remove(destructive_profile, client, users_container):
    # need an existing principal to add; use the built-in Administrator
    member_dn, err = await client.get_dn_for_objectsid("%s-500" % client.domainsid)
    if err is not None or member_dn is None:
        pytest.skip("built-in Administrator not resolvable")

    name = _rand("msldaptest_grp_")
    dn = "CN=%s,%s" % (name, users_container)
    ok, err = await client.add(
        dn,
        {
            "objectClass": ["top", "group"],
            "sAMAccountName": name,
            "groupType": 0x80000002,
        },
    )
    assert err is None, err
    try:
        _, err = await client.add_user_to_group(member_dn, dn)
        assert err is None, err
        members = await collect(client.get_group_members(dn), limit=10)
        member_dns = {getattr(m, "distinguishedName", None) for m in members}
        assert member_dn in member_dns

        _, err = await client.del_user_from_group(member_dn, dn)
        assert err is None, err
    finally:
        await client.delete(dn)


async def test_add_and_delete_computer(destructive_profile, client):
    computer, password, err = await client.add_computer()
    if err is not None and _is_confidentiality_error(err):
        pytest.skip("password writes require a confidential channel (use ldaps/encrypt): %s" % err)
    assert err is None, err
    assert computer is not None
    try:
        assert computer.sAMAccountName.endswith("$")
    finally:
        dn = computer.distinguishedName
        ok, err = await client.delete(dn)
        assert err is None, err


async def test_create_and_delete_user(destructive_profile, client, users_container):
    name = _rand("msldaptu_")
    dn = "CN=%s,%s" % (name, users_container)
    ok, err = await client.create_user_dn(dn, "Sup3rSecret!%s" % random.randint(1000, 9999))
    if err is not None and _is_confidentiality_error(err):
        # the object may have been created before the password step failed; clean up
        await client.delete(dn)
        pytest.skip("password writes require a confidential channel (use ldaps/encrypt): %s" % err)
    assert err is None, err
    try:
        fetched, err = await client.get_user(name)
        assert err is None, err
        assert fetched is not None
    finally:
        ok, err = await client.delete(dn)
        assert err is None, err
