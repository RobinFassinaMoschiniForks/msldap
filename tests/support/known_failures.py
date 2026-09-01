"""Helper to reference the confirmed-defect registry from tests."""
import os
import functools

import pytest

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a declared test dep
    yaml = None

_REGISTRY_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "known_failures.yml")


@functools.lru_cache(maxsize=1)
def _registry():
    if yaml is None:
        return {}
    with open(_REGISTRY_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def known_failure(kf_id: str):
    """Return a strict ``xfail`` marker whose reason comes from the registry.

    Strict mode means that if the underlying bug is fixed the test will XPASS
    and the suite will fail, prompting the registry entry to be retired.
    """
    entry = _registry().get(kf_id, {})
    summary = entry.get("summary", "unknown")
    reason = "%s: %s" % (kf_id, summary)
    return pytest.mark.xfail(reason=reason, strict=True)
