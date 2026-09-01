"""Offline tests for msldap.protocol.utils.calcualte_length (ASN.1 length decoding)."""
import pytest

from msldap.protocol.utils import calcualte_length

pytestmark = pytest.mark.unit


class TestCalculateLength:
    def test_short_form(self):
        # SEQUENCE (0x30), length 5 in short form -> total 5 + 2 header bytes
        assert calcualte_length(b"\x30\x05" + b"\x00" * 5) == 7

    def test_short_form_zero(self):
        assert calcualte_length(b"\x30\x00") == 2

    def test_short_form_max(self):
        # 0x7f == 127, still short form
        assert calcualte_length(b"\x30\x7f" + b"\x00" * 127) == 129

    def test_long_form_one_length_byte(self):
        # 0x81 -> next 1 byte is the length; 0x80 == 128
        # total = 128 (content) + 1 (length byte) + 2 (tag+len marker) = 131
        data = b"\x30\x81\x80" + b"\x00" * 128
        assert calcualte_length(data) == 131

    def test_long_form_two_length_bytes(self):
        # 0x82 -> next 2 bytes are the length (big endian); 0x0100 == 256
        # total = 256 + 2 (length bytes) + 2 = 260
        data = b"\x30\x82\x01\x00" + b"\x00" * 256
        assert calcualte_length(data) == 260
