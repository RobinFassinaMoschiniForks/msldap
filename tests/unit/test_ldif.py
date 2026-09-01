"""Offline tests for msldap.commons.ldif.MSLDAPLdiff.

Documents both working behavior and confirmed defects (tests/known_failures.yml).
"""
import asyncio
import os
import tempfile

import pytest

from msldap.commons.ldif import MSLDAPLdiff, LDIFIdx
from support.known_failures import known_failure

pytestmark = pytest.mark.unit


class TestLdifIdx:
    def test_length_computed(self):
        idx = LDIFIdx(10, 25)
        assert idx.length == 15


class TestParseEntry:
    def test_plain_attributes(self):
        ldiff = MSLDAPLdiff()
        raw = ["dn: CN=admin,DC=test,DC=corp", "sAMAccountName: admin", "objectClass: user"]
        entry = ldiff.parse_entry(raw)
        assert entry["dn"] == ["CN=admin,DC=test,DC=corp"]
        assert entry["sAMAccountName"] == ["admin"]
        assert entry["objectClass"] == ["user"]

    def test_multi_valued_attribute(self):
        ldiff = MSLDAPLdiff()
        raw = ["dn: X", "objectClass: top", "objectClass: person"]
        entry = ldiff.parse_entry(raw)
        assert entry["objectClass"] == ["top", "person"]

    def test_comments_and_blanks_ignored(self):
        ldiff = MSLDAPLdiff()
        raw = ["# a comment", "", "dn: X", "cn: value"]
        entry = ldiff.parse_entry(raw)
        assert entry["cn"] == ["value"]

    @known_failure("KF-0004")
    def test_base64_value_is_decoded(self):
        ldiff = MSLDAPLdiff()
        # 'aGVsbG8=' is base64 for b'hello'; LDIF uses '::' for base64 values
        raw = ["dn: X", "description:: aGVsbG8="]
        entry = ldiff.parse_entry(raw)
        assert entry["description"] == [b"hello"]


class TestBuildIndex:
    @known_failure("KF-0005")
    def test_build_index_on_simple_file(self):
        data = "dn: CN=admin,DC=test,DC=corp\nsAMAccountName: admin\nobjectClass: user\n\n"
        fd, path = tempfile.mkstemp(suffix=".ldif")
        os.close(fd)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
            ldiff = MSLDAPLdiff()
            ldiff.filename = path
            asyncio.run(ldiff.build_index())
            assert "DN: CN=ADMIN,DC=TEST,DC=CORP" in ldiff.dn_index
        finally:
            os.remove(path)
