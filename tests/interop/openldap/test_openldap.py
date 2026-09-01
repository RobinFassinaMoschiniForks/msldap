"""Interop tests against a non-AD (OpenLDAP) server.

Regression coverage for the AD-centric assumptions that used to break plain
LDAP interop:

* base-DN discovery falling back from ``defaultNamingContext`` (AD-only) to the
  RootDSE ``namingContexts`` / the URL-supplied base DN;
* ``get_ad_info()`` degrading gracefully instead of crashing on a non-AD server;
* paged search not tripping the server's hard ``sizeLimit`` and not assuming the
  paged-results control is always echoed on ``searchResDone``.

All tests are gated behind ``--run-live`` and skip when OpenLDAP is unreachable.
See ``conftest.py`` / ``docker-compose.yml`` in this directory.
"""
import pytest

pytestmark = pytest.mark.live

BASE_DN = "dc=example,dc=org"
# DNs guaranteed to exist by seed.ldif (a subtree search from the base sees all).
SEEDED_DNS = {
    "dc=example,dc=org",
    "ou=people,dc=example,dc=org",
    "ou=groups,dc=example,dc=org",
    "uid=alice,ou=people,dc=example,dc=org",
    "uid=bob,ou=people,dc=example,dc=org",
    "uid=carol,ou=people,dc=example,dc=org",
    "cn=admins,ou=groups,dc=example,dc=org",
}


async def _drain(agen):
    """Collect a msldap (result, err) async generator, raising on the first err."""
    out = []
    async for item, err in agen:
        if err is not None:
            raise err
        out.append(item)
    return out


class TestConnect:
    async def test_connect_discovers_base_dn(self, openldap_client):
        # The headline fix: OpenLDAP has no defaultNamingContext, so the base DN
        # must be resolved from the RootDSE namingContexts / the URL base DN.
        assert openldap_client._tree == BASE_DN

    async def test_rootdse_has_no_default_naming_context(self, openldap_client):
        info = openldap_client.get_server_info()
        assert info is not None
        assert "defaultNamingContext" not in info
        assert BASE_DN in info["namingContexts"]

    async def test_non_ad_info_is_absent_not_fatal(self, openldap_client):
        # get_ad_info() must return cleanly (None) rather than raising / returning
        # a bare None that blows up connect()'s tuple unpacking.
        info, err = await openldap_client.get_ad_info()
        assert err is None
        assert info is None


class TestPagedSearch:
    async def test_small_page_returns_all_entries(self, openldap_client):
        # page size 2 over 7 entries forces multiple pages: used to raise
        # LDAPSearchException 'sizeLimitExceeded' (request sizeLimit == page size)
        # and 'NoneType object is not iterable' (missing paged control on Done).
        openldap_client.ldap_query_page_size = 2
        entries = await _drain(
            openldap_client.pagedsearch("(objectClass=*)", ["dn"])
        )
        dns = {e["objectName"] for e in entries}
        assert SEEDED_DNS <= dns

    async def test_single_page_covers_all_entries(self, openldap_client):
        # Whole result set in one page: the server omits the paged-results control
        # from searchResDone, which must not crash the pager.
        openldap_client.ldap_query_page_size = 1000
        entries = await _drain(
            openldap_client.pagedsearch("(objectClass=*)", ["dn"])
        )
        dns = {e["objectName"] for e in entries}
        assert SEEDED_DNS <= dns

    async def test_filtered_search(self, openldap_client):
        entries = await _drain(
            openldap_client.pagedsearch("(uid=alice)", ["uid", "cn", "sn"])
        )
        assert len(entries) == 1
        attrs = entries[0]["attributes"]
        assert attrs.get("uid") in ("alice", ["alice"])


class TestExtendedOps:
    async def test_whoami(self, openldap_client):
        who, err = await openldap_client.whoami()
        assert err is None
        # RFC 4532 authzId; OpenLDAP returns the bound DN as dn:<DN>.
        assert who.lower().endswith("cn=admin,dc=example,dc=org")
