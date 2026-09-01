"""Offline ASN.1 encode/decode roundtrip tests for msldap.protocol.messages."""
import pytest

from msldap.protocol.messages import (
    LDAPMessage,
    BindRequest,
    protocolOp,
    AuthenticationChoice,
    SaslCredentials,
    SearchRequest,
    AttributeSelection,
    resultCode,
)
from msldap.protocol.query import query_syntax_converter

pytestmark = pytest.mark.unit


def _roundtrip(msg: LDAPMessage) -> LDAPMessage:
    raw = msg.dump()
    return LDAPMessage.load(raw)


class TestBindRequest:
    def test_simple_bind_roundtrip(self):
        br = BindRequest(
            {
                "version": 3,
                "name": b"cn=admin,dc=test,dc=corp",
                "authentication": AuthenticationChoice({"simple": b"Passw0rd!"}),
            }
        )
        msg = LDAPMessage({"messageID": 7, "protocolOp": protocolOp({"bindRequest": br})})
        dec = _roundtrip(msg)
        assert dec["messageID"].native == 7
        op = dec["protocolOp"].chosen
        assert op["version"].native == 3
        assert op["name"].native == b"cn=admin,dc=test,dc=corp"

    def test_sasl_bind_roundtrip(self):
        br = BindRequest(
            {
                "version": 3,
                "name": b"",
                "authentication": AuthenticationChoice(
                    {"sasl": SaslCredentials({"mechanism": b"GSS-SPNEGO", "credentials": b"\x01\x02"})}
                ),
            }
        )
        msg = LDAPMessage({"messageID": 1, "protocolOp": protocolOp({"bindRequest": br})})
        dec = _roundtrip(msg)
        sasl = dec["protocolOp"].chosen["authentication"].chosen
        assert sasl["mechanism"].native == b"GSS-SPNEGO"
        assert sasl["credentials"].native == b"\x01\x02"


class TestSearchRequest:
    def test_search_request_roundtrip(self):
        sr = SearchRequest(
            {
                "baseObject": b"dc=test,dc=corp",
                "scope": "wholeSubtree",
                "derefAliases": "neverDerefAliases",
                "sizeLimit": 1000,
                "timeLimit": 0,
                "typesOnly": False,
                "filter": query_syntax_converter("(&(objectClass=user)(cn=admin))"),
                "attributes": AttributeSelection([b"cn", b"sAMAccountName"]),
            }
        )
        msg = LDAPMessage({"messageID": 2, "protocolOp": protocolOp({"searchRequest": sr})})
        dec = _roundtrip(msg)
        op = dec["protocolOp"].chosen
        assert op["baseObject"].native == b"dc=test,dc=corp"
        assert op["scope"].native == "wholeSubtree"
        assert list(op["attributes"].native) == [b"cn", b"sAMAccountName"]


class TestEnums:
    def test_result_code_success(self):
        assert resultCode(0).native == "success"

    def test_result_code_invalid_credentials(self):
        # 49 == invalidCredentials
        assert resultCode(49).native == "invalidCredentials"
