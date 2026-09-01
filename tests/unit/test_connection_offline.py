"""Offline tests for MSLDAPClientConnection behaviour that does not need a socket."""
import pytest

from msldap.commons.factory import LDAPConnectionFactory

from support.known_failures import known_failure

pytestmark = pytest.mark.unit


class _RaisingAuth:
    """Stand-in auth context whose extra-info accessor blows up.

    This mirrors the real situation for simple/plain/anonymous binds where the
    underlying auth object cannot produce NTLM extra info.
    """

    def get_extra_info(self):
        raise ValueError("no extra info for this auth type")


def _offline_connection(url="ldap+ntlm-password://TEST\\victim:secret@10.0.0.2"):
    # get_connection() builds a fully-formed MSLDAPClientConnection without
    # opening any socket, which is exactly what we want for offline testing.
    conn = LDAPConnectionFactory.from_url(url).get_connection()
    return conn


@known_failure("KF-0006")
def test_get_extra_info_survives_auth_error():
    """When the auth layer raises, get_extra_info() should swallow it and
    return ``{'ntlm_data': None}`` -- not crash.

    Currently the except handler calls ``traceback.print_exc()`` while
    ``traceback`` is not imported at module scope, so it raises NameError.
    """
    conn = _offline_connection()
    conn.auth = _RaisingAuth()
    assert conn.get_extra_info() == {"ntlm_data": None}
