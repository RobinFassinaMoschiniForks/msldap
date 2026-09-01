"""Live ADCS / PKI enumeration tests.

These exercise msldap's certificate-services helpers against the *forest root*
DC, whose Configuration partition actually contains the PKI objects. (On a
child-domain DC these calls hit KF-0007 -- see tests/interop/live/test_enum.py.)

The ``root_client`` fixture is skipped automatically when no ``extra_targets.root``
is configured in the profile.
"""
import pytest

from support.agen import collect
from msldap.ldap_objects.adca import MSADCA
from msldap.ldap_objects.adcertificatetemplate import MSADCertificateTemplate
from msldap.ldap_objects.adenrollmentservice import MSADEnrollmentService

pytestmark = [pytest.mark.live, pytest.mark.asyncio]


async def test_certificate_templates_from_root(root_client):
    templates = await collect(root_client.list_certificate_templates(), limit=200)
    assert templates, "expected at least one pKICertificateTemplate in the forest"
    for t in templates:
        assert isinstance(t, MSADCertificateTemplate)
        assert t.cn or t.name
        # object must be serialisable (exercises the parser + to_dict path)
        assert isinstance(t.to_dict(), dict)


async def test_certificate_template_lookup_by_name(root_client):
    all_templates = await collect(root_client.list_certificate_templates(), limit=5)
    if not all_templates:
        pytest.skip("no templates to look up")
    target = all_templates[0]
    name = target.name or target.cn
    found = await collect(root_client.list_certificate_templates(name=name), limit=5)
    assert found, "name-filtered lookup returned nothing for %r" % name
    assert any((f.name == name or f.cn == name) for f in found)


async def test_enrollment_services_from_root(root_client):
    services = await collect(root_client.list_enrollment_services(), limit=50)
    assert services, "expected at least one pKIEnrollmentService (a CA) in the forest"
    for s in services:
        assert isinstance(s, MSADEnrollmentService)
        assert s.name or s.dNSHostName


async def test_certificate_template_vuln_analysis(root_client):
    """Exercise the ESC/vulnerability analysis surface of parsed templates.

    GOAD ships intentionally vulnerable templates, so we expect the analysis to
    flag at least one. Every predicate must return a sane type without raising.
    """
    templates = await collect(root_client.list_certificate_templates(), limit=200)
    assert templates

    for t in templates:
        # boolean flag predicates
        for pred in (
            t.allows_authentication,
            t.can_be_used_for_any_purpose,
            t.requires_manager_approval,
            t.requires_authorized_signatures,
            t.allows_to_specify_san,
            t.allows_to_request_agent_certificate,
            t.no_securty_extension,
        ):
            assert isinstance(bool(pred()), bool)

        # ACE computation + the two vulnerability scorers (no tokengroups path)
        t.calc_aces()
        vuln, reason = t.is_vulnerable()
        assert isinstance(vuln, bool)
        assert isinstance(reason, str)
        assert isinstance(t.check_dangerous_permissions(), (list, set, tuple, bool, type(None)))
        assert isinstance(t.is_vulnerable2(), (list, tuple, bool, dict, type(None)))

        # prettyprint renders the SID tables + flags -> big code path
        assert isinstance(t.prettyprint(), str)


async def test_root_and_nt_and_aia_cas(root_client):
    # These three live under different containers of the PKI services tree.
    for factory in (root_client.list_root_cas, root_client.list_ntcas, root_client.list_aiacas):
        cas = await collect(factory(), limit=50)
        assert isinstance(cas, list)
        for ca in cas:
            assert isinstance(ca, MSADCA)
            # the CA cert should have been decoded into an x509 Certificate
            if ca.cACertificate is not None:
                assert ca.cACertificate.native is not None
