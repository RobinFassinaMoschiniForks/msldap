"""Live end-to-end BloodHound collection test.

This exercises a very large surface of the library (schema dump, ACL dump,
users/computers/groups/gpos/ous/containers) and is therefore marked ``slow``.
"""
import os
import zipfile

import pytest

from msldap.bloodhound import MSLDAPDump2Bloodhound

pytestmark = [pytest.mark.live, pytest.mark.slow, pytest.mark.asyncio]


async def test_bloodhound_collection(client, tmp_path):
    bh = MSLDAPDump2Bloodhound(
        client,
        progress=False,
        output_path=str(tmp_path),
        use_mp=False,  # keep it single-process for deterministic test behavior
    )
    zippath, trusts, domainsid = await bh.run()

    assert os.path.isfile(zippath)
    with zipfile.ZipFile(zippath) as zf:
        names = zf.namelist()
    # BloodHound output must at least contain the core collection files
    joined = " ".join(names).lower()
    for expected in ("domains", "users", "groups", "computers"):
        assert expected in joined, "missing %s in %s" % (expected, names)
