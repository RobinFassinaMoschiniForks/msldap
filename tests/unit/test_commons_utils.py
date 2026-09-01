"""Offline tests for msldap.commons.utils."""
import datetime

import pytest

from msldap.commons import utils

pytestmark = pytest.mark.unit


class TestTimestampConversion:
    def test_datetime_timestamp_roundtrip(self):
        dt = datetime.datetime(2020, 1, 1, 12, 30, 15)
        ts = utils.datetime2timestamp(dt)
        assert utils.timestamp2datetime(ts) == dt

    def test_timestamp2datetime_accepts_int(self):
        # FILETIME epoch (0) -> 1601-01-01
        assert utils.timestamp2datetime(0) == datetime.datetime(1601, 1, 1)

    def test_timestamp2datetime_accepts_bytes(self):
        assert utils.timestamp2datetime(b"\x00" * 8) == datetime.datetime(1601, 1, 1)

    def test_win_timestamp_to_unix_zero(self):
        assert utils.win_timestamp_to_unix(0) == 0

    def test_win_timestamp_to_unix_known_value(self):
        # 116444736000000000 == unix epoch in FILETIME 100ns ticks
        assert utils.win_timestamp_to_unix(116444736000000000) == 0

    def test_win_timestamp_to_unix_accepts_str(self):
        assert utils.win_timestamp_to_unix("116444736000000000") == 0


class TestBhDtConvert:
    @pytest.mark.parametrize("value", [None, 0, "0", ""])
    def test_sentinels_return_minus_one(self, value):
        assert utils.bh_dt_convert(value) == -1

    def test_datetime_returns_epoch_seconds(self):
        dt = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        assert utils.bh_dt_convert(dt) == int(dt.timestamp())


class TestIpConversion:
    def test_bytes2ipv4(self):
        assert utils.bytes2ipv4(b"\x7f\x00\x00\x01") == "127.0.0.1"

    def test_bytes2ipv6(self):
        assert utils.bytes2ipv6(b"\x00" * 15 + b"\x01") == "::1"


class TestWrap:
    def test_wrap_splits_into_chunks(self):
        assert utils.wrap("abcdef", 2) == ["ab", "cd", "ef"]

    def test_wrap_uneven(self):
        assert utils.wrap("abcde", 2) == ["ab", "cd", "e"]


class TestKnownConstants:
    def test_functional_levels_present(self):
        assert utils.FUNCTIONAL_LEVELS[7] == "2016"

    def test_known_sids_present(self):
        assert utils.KNOWN_SIDS["S-1-5-32-544"] == "Administrators"
        assert utils.KNOWN_SIDS["S-1-1-0"] == "Everyone"
