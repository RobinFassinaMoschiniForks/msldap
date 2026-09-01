"""Offline tests for msldap.protocol.ldap_filter.soundex."""
import pytest

from msldap.protocol.ldap_filter.soundex import soundex, soundex_compare

pytestmark = pytest.mark.unit


class TestSoundex:
    @pytest.mark.parametrize(
        "word, code",
        [
            ("Robert", "R163"),
            ("Rupert", "R163"),
            # NOTE: this implementation does not truncate to 4 chars, and treats
            # H/W as plain vowels rather than the classic "separator" rule.
            ("Ashcraft", "A2613"),
            ("Tymczak", "T520"),
        ],
    )
    def test_known_codes(self, word, code):
        assert soundex(word) == code

    def test_output_has_min_width(self):
        # short inputs are right-padded with zeros to at least `scale` (4) chars
        assert len(soundex("A")) == 4
        assert soundex("A") == "A000"

    def test_scale_padding(self):
        assert soundex("Lee") == "L000"


class TestSoundexCompare:
    def test_similar_sounding_true(self):
        assert soundex_compare("Robert", "Rupert") is True

    def test_different_false(self):
        assert soundex_compare("Robert", "Xylophone") is False
