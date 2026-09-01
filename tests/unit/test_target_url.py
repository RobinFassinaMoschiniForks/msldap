"""Offline tests for MSLDAPTarget URL parsing."""
import pytest

from asysocks.unicomm.common.target import UniProto

from msldap.commons.target import MSLDAPTarget

pytestmark = pytest.mark.unit


class TestSchemeToProtocolAndPort:
    @pytest.mark.parametrize(
        "url, proto, port, ssl",
        [
            ("ldap://10.0.0.1", UniProto.CLIENT_TCP, 389, False),
            ("ldaps://10.0.0.1", UniProto.CLIENT_SSL_TCP, 636, True),
            ("ldap-tcp://10.0.0.1", UniProto.CLIENT_TCP, 389, False),
            ("ldap-ssl://10.0.0.1", UniProto.CLIENT_SSL_TCP, 636, True),
            ("gc://10.0.0.1", UniProto.CLIENT_TCP, 3268, False),
            ("gc-ssl://10.0.0.1", UniProto.CLIENT_SSL_TCP, 3269, True),
        ],
    )
    def test_defaults(self, url, proto, port, ssl):
        t = MSLDAPTarget.from_url(url)
        assert t.protocol == proto
        assert t.port == port
        assert t.is_ssl() is ssl

    def test_explicit_port_overrides_default(self):
        t = MSLDAPTarget.from_url("ldap://10.0.0.1:1389")
        assert t.port == 1389

    def test_unknown_scheme_raises(self):
        with pytest.raises(Exception):
            MSLDAPTarget.from_url("foobar://10.0.0.1")

    def test_ldap_udp_not_implemented(self):
        with pytest.raises(NotImplementedError):
            MSLDAPTarget.from_url("ldap-udp://10.0.0.1")


class TestTargetComponents:
    def test_host_and_credentials_parsed(self):
        t = MSLDAPTarget.from_url("ldap://TEST\\victim:secret@10.0.0.2")
        assert t.ip == "10.0.0.2"

    def test_tree_path_stripped_to_base_dn(self):
        # The base DN in the URL path must come back as a usable DN, not
        # '/DC=test,DC=corp/'. The surrounding slashes are stripped so the value
        # can be used directly as a search base (important for non-AD servers
        # where the base DN can't be discovered from the RootDSE).
        t = MSLDAPTarget.from_url("ldap://10.0.0.2/DC=test,DC=corp/")
        assert t.tree == "DC=test,DC=corp"

    def test_no_tree_is_none(self):
        t = MSLDAPTarget.from_url("ldap://10.0.0.2")
        assert t.tree is None

    def test_pagesize_and_rate_params(self):
        t = MSLDAPTarget.from_url("ldap://10.0.0.2/?pagesize=250&rate=5")
        assert t.ldap_query_page_size == 250
        assert t.ldap_query_ratelimit == 5

    def test_pagesize_default(self):
        t = MSLDAPTarget.from_url("ldap://10.0.0.2")
        assert t.ldap_query_page_size == 1000
        assert t.ldap_query_ratelimit == 0


class TestTargetHelpers:
    def test_get_host_ldap(self):
        t = MSLDAPTarget.from_url("ldap://10.0.0.2:389")
        assert t.get_host() == "ldap://10.0.0.2:389"

    def test_get_host_ldaps(self):
        t = MSLDAPTarget.from_url("ldaps://10.0.0.2")
        assert t.get_host() == "ldaps://10.0.0.2:636"

    def test_to_target_string_shape(self):
        t = MSLDAPTarget.from_url("ldap://host.test.corp")
        s = t.to_target_string()
        assert s.startswith("ldap/")

    def test_str_does_not_raise(self):
        t = MSLDAPTarget.from_url("ldaps://10.0.0.2")
        assert "MSLDAPTarget" in str(t)
