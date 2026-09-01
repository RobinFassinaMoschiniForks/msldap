"""Offline tests for the LDAP filter parser/matcher (msldap.protocol.ldap_filter)."""
import pytest

from msldap.protocol.ldap_filter import Filter as LF
from msldap.protocol.ldap_filter.filter import LDAPBase, GroupAnd, GroupOr, GroupNot, Filter

pytestmark = pytest.mark.unit


class TestParseRoundTrip:
    @pytest.mark.parametrize(
        "expr",
        [
            "(cn=admin)",
            "(objectClass=*)",
            "(&(objectClass=user)(sAMAccountName=admin))",
            "(|(cn=a)(cn=b))",
            "(!(cn=admin))",
            "(&(objectClass=user)(|(cn=a)(cn=b))(!(memberOf=x)))",
        ],
    )
    def test_parse_then_str_is_stable(self, expr):
        parsed = LF.parse(expr)
        # re-stringifying and re-parsing must yield the same canonical string
        assert str(LF.parse(str(parsed))) == str(parsed)

    def test_and_parses_to_groupand(self):
        assert isinstance(LF.parse("(&(a=1)(b=2))"), GroupAnd)

    def test_or_parses_to_groupor(self):
        assert isinstance(LF.parse("(|(a=1)(b=2))"), GroupOr)

    def test_not_parses_to_groupnot(self):
        assert isinstance(LF.parse("(!(a=1))"), GroupNot)

    def test_simple_parses_to_filter(self):
        assert isinstance(LF.parse("(a=1)"), Filter)

    def test_whitespace_is_stripped(self):
        # the parser strips insignificant whitespace between elements
        parsed = LF.parse("(& (objectClass=user) (cn=admin) )")
        assert isinstance(parsed, GroupAnd)


class TestEscape:
    def test_escape_special_chars(self):
        assert LDAPBase.escape("a*b(c)\\") == "a\\2ab\\28c\\29\\5c"

    def test_escape_null_byte(self):
        assert LDAPBase.escape("a\x00b") == "a\\00b"

    def test_unescape_roundtrip(self):
        original = "a*b(c)\\"
        assert LDAPBase.unescape(LDAPBase.escape(original)) == original


class TestMatch:
    def test_equality_match(self):
        f = LF.parse("(cn=admin)")
        assert f.match({"cn": "admin"}) is True
        assert f.match({"cn": "bob"}) is False

    def test_missing_attribute_no_match(self):
        f = LF.parse("(cn=admin)")
        assert f.match({"sn": "admin"}) is False

    def test_presence_match(self):
        f = LF.parse("(cn=*)")
        assert f.match({"cn": "anything"}) is True
        assert f.match({"sn": "x"}) is False

    def test_substring_match(self):
        f = LF.parse("(cn=adm*)")
        assert f.match({"cn": "administrator"}) is True
        assert f.match({"cn": "guest"}) is False

    def test_and_match(self):
        f = LF.parse("(&(cn=admin)(sn=root))")
        assert f.match({"cn": "admin", "sn": "root"}) is True
        assert f.match({"cn": "admin", "sn": "other"}) is False

    def test_or_match(self):
        f = LF.parse("(|(cn=a)(cn=b))")
        assert f.match({"cn": "b"}) is True
        assert f.match({"cn": "c"}) is False

    def test_not_match(self):
        f = LF.parse("(!(cn=admin))")
        assert f.match({"cn": "bob"}) is True
        assert f.match({"cn": "admin"}) is False

    def test_gte_lte_numeric(self):
        assert LF.parse("(uid>=5)").match({"uid": "10"}) is True
        assert LF.parse("(uid>=5)").match({"uid": "1"}) is False
        assert LF.parse("(uid<=5)").match({"uid": "1"}) is True

    def test_match_list_valued_attribute(self):
        f = LF.parse("(memberOf=admins)")
        assert f.match({"memberOf": ["users", "admins"]}) is True


class TestParseErrors:
    @pytest.mark.parametrize("expr", ["", "(cn=admin", "cn=admin)", "()"])
    def test_malformed_filters_raise(self, expr):
        with pytest.raises(Exception):
            LF.parse(expr)


class TestParseExotic:
    """Broader coverage of the recursive-descent parser's grammar branches."""

    @pytest.mark.parametrize(
        "expr",
        [
            "(cn=a*b*c)",                       # multi-wildcard substring
            "(cn=*a*)",
            "(cn~=admin)",                      # approx
            "(uidNumber>=1000)",
            "(uidNumber<=1000)",
            "(cn=caf\\c3\\a9)",                 # hex-escaped bytes
            "(cn=a\\2ab)",                       # escaped '*'
            "(1.2.840.113556.1.4.1=x)",         # OID attribute type
            "(&(a=1)(|(b=2)(!(c=3)))(d=*))",    # deep nesting
        ],
    )
    def test_parses_without_error(self, expr):
        parsed = LF.parse(expr)
        assert parsed is not None
        assert str(parsed)

    def test_deeply_nested_roundtrip(self):
        expr = "(&(objectClass=user)(|(cn=a)(cn=b))(!(memberOf=x)))"
        parsed = LF.parse(expr)
        assert str(LF.parse(str(parsed))) == str(parsed)


class TestPrettyPrint:
    def test_indented_output_contains_newlines(self):
        parsed = LF.parse("(&(a=1)(b=2))")
        pretty = parsed.to_string(indent=True)
        assert "(&" in pretty
        assert "\n" in pretty

    def test_flat_output_has_no_newlines(self):
        parsed = LF.parse("(&(a=1)(b=2))")
        assert "\n" not in str(parsed)


class TestBuilderApi:
    """The fluent Attribute/Filter builder used to construct filters in code."""

    def test_present(self):
        assert str(Filter.attribute("cn").present()) == "(cn=*)"

    def test_equal_to_escapes(self):
        f = Filter.attribute("cn").equal_to("a*b")
        assert str(f) == "(cn=a\\2ab)"

    def test_starts_ends_contains(self):
        assert str(Filter.attribute("cn").starts_with("adm")) == "(cn=adm*)"
        assert str(Filter.attribute("cn").ends_with("min")) == "(cn=*min)"
        assert str(Filter.attribute("cn").contains("dmi")) == "(cn=*dmi*)"

    def test_comparators(self):
        assert str(Filter.attribute("uid").gte(5)) == "(uid>=5)"
        assert str(Filter.attribute("uid").lte(5)) == "(uid<=5)"
        assert str(Filter.attribute("cn").approx("admin")) == "(cn~=admin)"

    def test_and_or_not_constructors(self):
        a = Filter.attribute("a").equal_to("1")
        b = Filter.attribute("b").equal_to("2")
        assert isinstance(Filter.AND([a, b]), GroupAnd)
        assert isinstance(Filter.OR([a, b]), GroupOr)
        assert isinstance(Filter.NOT(a), GroupNot)

    def test_not_with_multiple_filters_raises(self):
        a = Filter.attribute("a").equal_to("1")
        b = Filter.attribute("b").equal_to("2")
        with pytest.raises(Exception):
            Filter.NOT([a, b])


class TestMatchExtended:
    def test_multi_wildcard_substring(self):
        f = LF.parse("(cn=a*c*e)")
        assert f.match({"cn": "abcde"}) is True
        assert f.match({"cn": "ace"}) is True
        assert f.match({"cn": "abcd"}) is False

    def test_approx_soundex(self):
        # Robert and Rupert share a soundex code
        f = LF.parse("(sn~=Robert)")
        assert f.match({"sn": "Rupert"}) is True
        assert f.match({"sn": "Xavier"}) is False

    def test_gte_lte_string_fallback(self):
        # non-numeric values fall back to lexicographic comparison
        assert LF.parse("(cn>=m)").match({"cn": "z"}) is True
        assert LF.parse("(cn<=m)").match({"cn": "a"}) is True

    def test_case_insensitive_equality(self):
        f = LF.parse("(cn=ADMIN)")
        assert f.match({"cn": "admin"}) is True
