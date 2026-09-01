"""Offline parsing tests for the remaining msldap.ldap_objects classes."""
import pytest

from msldap.ldap_objects.adcomp import MSADMachine
from msldap.ldap_objects.adgroup import MSADGroup
from msldap.ldap_objects.adou import MSADOU
from msldap.ldap_objects.adgpo import MSADGPO
from msldap.ldap_objects.adcontainer import MSADContainer
from msldap.ldap_objects.common import MSLDAP_UAC
from support.builders import make_search_entry

pytestmark = pytest.mark.unit


class TestMSADMachine:
    def _entry(self, **attrs):
        base = {
            "sAMAccountName": "DC01$",
            "distinguishedName": "CN=DC01,OU=Domain Controllers,DC=test,DC=corp",
            "objectSid": "S-1-5-21-1-2-3-1001",
            "primaryGroupID": 516,
            "userAccountControl": 0x82000,  # SERVER_TRUST + TRUSTED_FOR_DELEGATION
            "dNSHostName": "dc01.test.corp",
            "operatingSystem": "Windows Server 2019",
        }
        base.update(attrs)
        return make_search_entry(base["distinguishedName"], base)

    def test_from_ldap_basic(self):
        m = MSADMachine.from_ldap(self._entry())
        assert m.sAMAccountName == "DC01$"
        assert m.dNSHostName == "dc01.test.corp"

    def test_uac_intflag(self):
        m = MSADMachine.from_ldap(self._entry())
        assert isinstance(m.userAccountControl, MSLDAP_UAC)

    def test_to_dict(self):
        d = MSADMachine.from_ldap(self._entry()).to_dict()
        assert d["sAMAccountName"] == "DC01$"

    def test_to_bh_unconstrained_delegation(self):
        bh = MSADMachine.from_ldap(self._entry()).to_bh("test.corp")
        assert bh["ObjectIdentifier"] == "S-1-5-21-1-2-3-1001"
        assert bh["Properties"]["unconstraineddelegation"] is True
        assert bh["PrimaryGroupSID"] == "S-1-5-21-1-2-3-516"

    def test_to_bh_no_uac(self):
        # to_bh must tolerate a missing userAccountControl
        bh = MSADMachine.from_ldap(self._entry(userAccountControl=None)).to_bh("test.corp")
        assert bh["Properties"]["enabled"] is True


class TestMSADGroup:
    def _entry(self, **attrs):
        base = {
            "cn": "Domain Admins",
            "name": "Domain Admins",
            "sAMAccountName": "Domain Admins",
            "distinguishedName": "CN=Domain Admins,CN=Users,DC=test,DC=corp",
            "objectSid": "S-1-5-21-1-2-3-512",
            "adminCount": 1,
        }
        base.update(attrs)
        return make_search_entry(base["distinguishedName"], base)

    def test_from_ldap(self):
        g = MSADGroup.from_ldap(self._entry())
        assert g.sAMAccountName == "Domain Admins"

    def test_description_list_collapsed(self):
        g = MSADGroup.from_ldap(self._entry(description=["one"]))
        assert g.description == "one"

    def test_description_multi_joined(self):
        g = MSADGroup.from_ldap(self._entry(description=["a", "b"]))
        assert g.description == "a, b"

    def test_to_bh_highvalue_domain_admins(self):
        bh = MSADGroup.from_ldap(self._entry()).to_bh("test.corp")
        # SID ending in -512 is high value
        assert bh["Properties"]["highvalue"] is True
        assert bh["Properties"]["admincount"] is True

    def test_to_bh_lowvalue_group(self):
        bh = MSADGroup.from_ldap(
            self._entry(objectSid="S-1-5-21-1-2-3-1111", adminCount=None)
        ).to_bh("test.corp")
        assert bh["Properties"]["highvalue"] is False


class TestMSADOU:
    def _entry(self, **attrs):
        base = {
            "name": "Workstations",
            "distinguishedName": "OU=Workstations,DC=test,DC=corp",
            "objectGUID": "{11111111-1111-1111-1111-111111111111}",
        }
        base.update(attrs)
        return make_search_entry(base["distinguishedName"], base)

    def test_from_ldap(self):
        ou = MSADOU.from_ldap(self._entry())
        assert ou.name == "Workstations"

    def test_to_bh(self):
        bh = MSADOU.from_ldap(self._entry()).to_bh("test.corp", "S-1-5-21-1-2-3")
        assert bh["ObjectIdentifier"] == "{11111111-1111-1111-1111-111111111111}".upper()
        assert bh["Properties"]["name"] == "WORKSTATIONS@TEST.CORP"


class TestMSADGPO:
    def _entry(self, **attrs):
        base = {
            "cn": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "displayName": "Default Domain Policy",
            "distinguishedName": "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,DC=test,DC=corp",
            "objectGUID": "{22222222-2222-2222-2222-222222222222}",
            "gPCFileSysPath": "\\\\test.corp\\SysVol\\test.corp\\Policies\\{GUID}",
        }
        base.update(attrs)
        return make_search_entry(base["distinguishedName"], base)

    def test_from_ldap(self):
        g = MSADGPO.from_ldap(self._entry())
        assert g.displayName == "Default Domain Policy"

    def test_to_bh(self):
        bh = MSADGPO.from_ldap(self._entry()).to_bh("test.corp", "S-1-5-21-1-2-3")
        assert bh["Properties"]["name"] == "DEFAULT DOMAIN POLICY@TEST.CORP"
        assert bh["Properties"]["gpcpath"].startswith("\\\\TEST.CORP")


class TestMSADContainer:
    def _entry(self, **attrs):
        base = {
            "name": "Users",
            "distinguishedName": "CN=Users,DC=test,DC=corp",
            "objectGUID": "{33333333-3333-3333-3333-333333333333}",
        }
        base.update(attrs)
        return make_search_entry(base["distinguishedName"], base)

    def test_from_ldap(self):
        c = MSADContainer.from_ldap(self._entry())
        assert c.name == "Users"

    def test_to_bh(self):
        bh = MSADContainer.from_ldap(self._entry()).to_bh("test.corp", "S-1-5-21-1-2-3")
        assert bh["ObjectIdentifier"] == "{33333333-3333-3333-3333-333333333333}".upper()
        assert bh["Properties"]["name"] == "Users"
