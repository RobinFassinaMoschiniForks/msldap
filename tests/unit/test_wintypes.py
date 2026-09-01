"""Offline byte-level parsing tests for msldap.wintypes."""
import struct

import pytest

from msldap.wintypes.dnsp.structures.dnsrecord import (
    DNS_RECORD,
    DNS_RECORD_TYPE,
    DNS_RPC_RECORD_A,
    DNS_RPC_RECORD_AAAA,
)
from msldap.wintypes.managedpassword import MSDS_MANAGEDPASSWORD_BLOB

pytestmark = pytest.mark.unit


class TestDnsRecordRoundTrip:
    def test_a_record_roundtrip(self):
        rec = DNS_RECORD.create_A("192.168.1.50", serial=7, ttlseconds=300)
        dec = DNS_RECORD.from_bytes(rec.to_bytes())
        assert dec.Type == DNS_RECORD_TYPE.A
        assert dec.Serial == 7
        assert dec.TtlSeconds == 300
        assert str(dec.get_formatted()) == "192.168.1.50"

    def test_aaaa_record_roundtrip(self):
        rec = DNS_RECORD.create_AAAA("fe80::1", serial=9)
        dec = DNS_RECORD.from_bytes(rec.to_bytes())
        assert dec.Type == DNS_RECORD_TYPE.AAAA
        assert str(dec.get_formatted()) == "fe80::1"

    def test_datalength_matches_data(self):
        rec = DNS_RECORD.create_A("10.0.0.1", serial=1)
        dec = DNS_RECORD.from_bytes(rec.to_bytes())
        assert dec.DataLength == len(dec.Data) == 4

    def test_zero_record(self):
        rec = DNS_RECORD.create_zero(serial=1, data=b"")
        dec = DNS_RECORD.from_bytes(rec.to_bytes())
        assert dec.Type == DNS_RECORD_TYPE.ZERO
        assert dec.get_formatted() is None


class TestDnsRpcRecordParsers:
    def test_a_from_bytes(self):
        assert DNS_RPC_RECORD_A.from_bytes(b"\x7f\x00\x00\x01").IpAddress == "127.0.0.1"

    def test_aaaa_from_bytes(self):
        rec = DNS_RPC_RECORD_AAAA.from_bytes(b"\x00" * 15 + b"\x01")
        assert rec.IpAddress == "::1"


class TestManagedPasswordBlob:
    def _blob(self):
        current_pw = bytes(range(32))
        # Version=1, Reserved=0, Length=64, CurrentPwOff=16, PrevPwOff=0,
        # QueryPwIntervalOff=48, UnchangedPwIntervalOff=56
        header = struct.pack("<HHIHHHH", 1, 0, 64, 16, 0, 48, 56)
        return header + current_pw + b"\x11" * 8 + b"\x22" * 8

    def test_version_and_offsets(self):
        blob = MSDS_MANAGEDPASSWORD_BLOB.from_bytes(self._blob())
        assert blob.Version == 1
        assert blob.CurrentPasswordOffset == 16

    def test_current_password_extracted(self):
        blob = MSDS_MANAGEDPASSWORD_BLOB.from_bytes(self._blob())
        assert blob.CurrentPassword == bytes(range(32))

    def test_nt_hash_is_md4_hex(self):
        blob = MSDS_MANAGEDPASSWORD_BLOB.from_bytes(self._blob())
        # md4 hex digest is always 32 hex chars
        assert len(blob.nt_hash) == 32
        int(blob.nt_hash, 16)  # must be valid hex
