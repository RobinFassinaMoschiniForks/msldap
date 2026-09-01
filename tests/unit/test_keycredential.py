"""Offline tests for msldap.commons.keycredential (Shadow Credentials helper)."""
import struct

import pytest

from msldap.commons.keycredential import KeyCredential
from support.known_failures import known_failure

pytestmark = pytest.mark.unit

# A fixed device id + time keep generation deterministic (and fast-ish).
_DEVICE_ID = b"\x11" * 16
_CURRENT_TIME = 133000000000000000


@pytest.fixture(scope="module")
def keycred():
    # 1024-bit key keeps the test fast; we only care about serialization shape.
    return KeyCredential.generate_self_signed_certificate(
        "CN=testuser", kSize=1024, deviceId=_DEVICE_ID, currentTime=_CURRENT_TIME
    )


class TestGeneration:
    def test_version_is_200(self, keycred):
        assert keycred.version == 0x200

    def test_pubkey_starts_with_rsa1_magic(self, keycred):
        assert keycred.pubkey.startswith(b"RSA1")

    def test_thumbprint_is_set(self, keycred):
        assert isinstance(keycred.thumbprint, str)
        assert len(keycred.thumbprint) > 0


class TestBinarySerialization:
    def test_dump_binary_version_prefix(self, keycred):
        bd = keycred.dumpBinary()
        # first 4 bytes are the little-endian version (0x200)
        assert struct.unpack("<L", bd[:4])[0] == 0x200

    def test_dn_with_binary_string_shape(self, keycred):
        dn = keycred.toDNWithBinary2String("CN=owner,DC=test,DC=corp")
        assert dn.startswith("B:")
        assert dn.endswith("CN=owner,DC=test,DC=corp")
        # B:<len>:<hex>:<owner>
        parts = dn.split(":", 3)
        declared_len = int(parts[1])
        assert len(parts[2]) == declared_len


class TestPfxRoundTrip:
    def test_pfx_data_export(self, keycred):
        # export must succeed and produce non-empty bytes
        data = keycred.to_pfx_data("Passw0rd!")
        assert isinstance(data, (bytes, bytearray))
        assert len(data) > 0

    @known_failure("KF-0003")
    def test_pfx_data_import_roundtrip(self, keycred):
        data = keycred.to_pfx_data("Passw0rd!")
        loaded = KeyCredential.from_pfx_data(data, "Passw0rd!")
        assert loaded.pubkey == keycred.pubkey
