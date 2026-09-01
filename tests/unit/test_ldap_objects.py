"""Offline tests for msldap.ldap_objects parsing (from_ldap / to_dict / to_bh)."""
import pytest

from msldap.ldap_objects.aduser import MSADUser
from msldap.ldap_objects.common import MSLDAP_UAC, vn
from support.builders import make_search_entry

pytestmark = pytest.mark.unit


class TestVn:
    def test_empty_list_is_none(self):
        assert vn([]) is None

    def test_list_is_joined(self):
        assert vn(["a", "b"]) == "a|b"

    def test_scalar_passthrough(self):
        assert vn("x") == "x"


class TestMSLDAPUAC:
    def test_normal_account_flag(self):
        uac = MSLDAP_UAC(0x200)
        assert MSLDAP_UAC.NORMAL_ACCOUNT in uac

    def test_disabled_flag(self):
        uac = MSLDAP_UAC(0x202)
        assert MSLDAP_UAC.ACCOUNTDISABLE in uac
        assert MSLDAP_UAC.NORMAL_ACCOUNT in uac

    def test_dont_expire_password(self):
        uac = MSLDAP_UAC(0x10200)
        assert MSLDAP_UAC.DONT_EXPIRE_PASSWD in uac


class TestMSADUserFromLdap:
    def _entry(self, **attrs):
        base = {
            "sAMAccountName": "admin",
            "cn": "admin",
            "distinguishedName": "CN=admin,DC=test,DC=corp",
            "objectSid": "S-1-5-21-1-2-3-500",
            "userAccountControl": 0x200,
        }
        base.update(attrs)
        return make_search_entry("CN=admin,DC=test,DC=corp", base)

    def test_basic_fields(self):
        u = MSADUser.from_ldap(self._entry())
        assert u.sAMAccountName == "admin"
        assert u.distinguishedName == "CN=admin,DC=test,DC=corp"

    def test_uac_parsed_to_intflag(self):
        u = MSADUser.from_ldap(self._entry(userAccountControl=0x200))
        assert isinstance(u.userAccountControl, MSLDAP_UAC)
        assert MSLDAP_UAC.NORMAL_ACCOUNT in u.userAccountControl

    def test_to_dict_roundtrips_core_fields(self):
        u = MSADUser.from_ldap(self._entry())
        d = u.to_dict()
        assert d["sAMAccountName"] == "admin"
        assert d["objectSid"] == "S-1-5-21-1-2-3-500"

    def test_missing_attribute_is_none(self):
        u = MSADUser.from_ldap(self._entry())
        assert u.title is None


class TestMSADUserToBloodhound:
    def _entry(self, **attrs):
        base = {
            "sAMAccountName": "admin",
            "objectSid": "S-1-5-21-1-2-3-500",
            "primaryGroupID": 513,
            "userAccountControl": 0x200,
        }
        base.update(attrs)
        return make_search_entry("CN=admin,DC=test,DC=corp", base)

    def test_object_identifier_is_sid(self):
        bh = MSADUser.from_ldap(self._entry()).to_bh("test.corp")
        assert bh["ObjectIdentifier"] == "S-1-5-21-1-2-3-500"

    def test_primary_group_sid_computed(self):
        bh = MSADUser.from_ldap(self._entry()).to_bh("test.corp")
        assert bh["PrimaryGroupSID"] == "S-1-5-21-1-2-3-513"

    def test_enabled_reflects_uac(self):
        enabled = MSADUser.from_ldap(self._entry(userAccountControl=0x200)).to_bh("test.corp")
        disabled = MSADUser.from_ldap(self._entry(userAccountControl=0x202)).to_bh("test.corp")
        assert enabled["Properties"]["enabled"] is True
        assert disabled["Properties"]["enabled"] is False

    def test_hasspn_reflects_spn(self):
        with_spn = MSADUser.from_ldap(
            self._entry(servicePrincipalName=["HTTP/host"])
        ).to_bh("test.corp")
        without = MSADUser.from_ldap(self._entry()).to_bh("test.corp")
        assert with_spn["Properties"]["hasspn"] is True
        assert without["Properties"]["hasspn"] is False

    def test_name_is_upper_at_domain(self):
        bh = MSADUser.from_ldap(self._entry()).to_bh("test.corp")
        assert bh["Properties"]["name"] == "ADMIN@TEST.CORP"
