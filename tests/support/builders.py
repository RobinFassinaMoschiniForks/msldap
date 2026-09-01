"""Builders for synthetic LDAP data used by offline unit tests.

These helpers construct the plain dict shapes that msldap's higher layers
expect (e.g. the output of ``convert_result``), so object-parsing code can be
exercised without a live directory.
"""
from typing import Dict, List


def make_search_entry(object_name: str, attributes: Dict[str, object]) -> Dict[str, object]:
    """Return an entry shaped like ``msldap.protocol.typeconversion.convert_result`` output.

    ``attributes`` are already-converted (native python) values, matching what
    ``*.from_ldap`` consumers read via ``entry['attributes'].get(...)``.
    """
    return {
        "objectName": object_name,
        "attributes": dict(attributes),
    }


def make_raw_attributes(attributes: Dict[str, List[bytes]]) -> List[Dict[str, object]]:
    """Return the raw wire-shaped attribute list consumed by ``convert_attributes``.

    Example::

        make_raw_attributes({"sAMAccountName": [b"admin"]})
    """
    res = []
    for key, values in attributes.items():
        res.append({"type": key.encode(), "attributes": list(values)})
    return res
