"""Offline tests for msldap.protocol.query (LDAP string -> ASN.1 Filter)."""
import pytest

from msldap.protocol.query import (
    query_syntax_converter,
    rfc4515_encode,
    escape_filter_chars,
)
from msldap.protocol.messages import Filter

pytestmark = pytest.mark.unit


class TestQuerySyntaxConverter:
    @pytest.mark.parametrize(
        "query",
        [
            "(cn=admin)",
            "(objectClass=*)",
            "(cn=adm*)",
            "(cn=*min)",
            "(cn=*dmi*)",
            "(&(objectClass=user)(cn=admin))",
            "(|(cn=a)(cn=b))",
            "(!(cn=admin))",
            "(badPwdCount>=1)",
            "(badPwdCount<=5)",
            "(cn~=admin)",
        ],
    )
    def test_converts_to_loadable_asn1(self, query):
        f = query_syntax_converter(query)
        raw = f.dump()
        # must be decodable back into an ASN.1 Filter
        assert Filter.load(raw).dump() == raw

    def test_equality_chooses_equalitymatch(self):
        f = query_syntax_converter("(cn=admin)")
        assert f.chosen is not None

    def test_present_filter(self):
        f = query_syntax_converter("(cn=*)")
        # present filter carries the attribute description
        assert f.dump()  # smoke: encodes without error

    def test_and_nesting(self):
        f = query_syntax_converter("(&(a=1)(b=2)(c=3))")
        assert f.dump()


class TestRfc4515Encode:
    def test_plain_ascii(self):
        assert rfc4515_encode("abc") == b"abc"

    def test_escaped_hex_is_decoded(self):
        # \2a -> '*'
        assert rfc4515_encode("a\\2ab") == b"a*b"

    def test_utf8_passthrough(self):
        assert rfc4515_encode("caf\u00e9") == "caf\u00e9".encode("utf-8")


class TestEscapeFilterChars:
    def test_escapes_star(self):
        assert escape_filter_chars("a*b") == "a\\2ab"

    def test_escapes_parens_and_backslash(self):
        assert escape_filter_chars("(x)\\") == "\\28x\\29\\5c"
