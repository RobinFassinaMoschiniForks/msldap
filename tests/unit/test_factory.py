"""Offline tests for LDAPConnectionFactory."""
import copy

import pytest

from msldap.commons.factory import LDAPConnectionFactory
from msldap.commons.target import MSLDAPTarget

pytestmark = pytest.mark.unit


def test_from_url_builds_target_and_credential():
    fact = LDAPConnectionFactory.from_url("ldap+ntlm-password://TEST\\victim:secret@10.0.0.2")
    assert isinstance(fact.get_target(), MSLDAPTarget)
    assert fact.get_credential() is not None


def test_get_target_returns_copy():
    fact = LDAPConnectionFactory.from_url("ldap://10.0.0.2")
    t1 = fact.get_target()
    t2 = fact.get_target()
    assert t1 is not t2
    assert t1.ip == t2.ip == "10.0.0.2"


def test_get_credential_returns_copy():
    fact = LDAPConnectionFactory.from_url("ldap+ntlm-password://TEST\\victim:secret@10.0.0.2")
    c1 = fact.get_credential()
    c2 = fact.get_credential()
    assert c1 is not c2


def test_get_client_uses_target():
    fact = LDAPConnectionFactory.from_url("ldap://10.0.0.2")
    client = fact.get_client()
    assert client.target.ip == "10.0.0.2"


def test_get_connection_uses_target():
    fact = LDAPConnectionFactory.from_url("ldap://10.0.0.2")
    conn = fact.get_connection()
    assert conn.target.ip == "10.0.0.2"


def test_newtarget_overrides_host_but_keeps_settings():
    fact = LDAPConnectionFactory.from_url("ldaps://10.0.0.2:1636/?pagesize=250")
    client = fact.get_client_newtarget("dc.other.corp")
    assert client.target.get_hostname_or_ip() == "dc.other.corp"
    assert client.target.port == 1636
    assert client.target.ldap_query_page_size == 250


def test_connection_newtarget_overrides_host():
    fact = LDAPConnectionFactory.from_url("ldaps://10.0.0.2:1636")
    conn = fact.get_connection_newtarget("dc.other.corp")
    assert conn.target.get_hostname_or_ip() == "dc.other.corp"
    assert conn.target.port == 1636


def test_str_lists_fields():
    fact = LDAPConnectionFactory.from_url("ldap://10.0.0.2")
    assert "LDAPConnectionFactory" in str(fact)
