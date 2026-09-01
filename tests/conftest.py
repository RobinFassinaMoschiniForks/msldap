"""Root pytest configuration for the msldap test suite.

This module intentionally establishes NO network connections. Its only job is
to implement the collection policy:

* Offline ``unit`` tests always run.
* Tests marked ``live`` / ``destructive`` / ``slow`` are skipped by default and
  only run when the matching ``--run-*`` opt-in flag is passed.

The design mirrors the staged/opt-in architecture used by the sibling
``aiosmb`` project so that the default ``pytest`` invocation is always safe to
run in CI with no lab access.
"""
import pytest

# marker name -> CLI flag that enables it
_OPT_IN_MARKERS = (
    ("live", "--run-live"),
    ("destructive", "--run-destructive"),
    ("slow", "--run-slow"),
)


def pytest_addoption(parser):
    group = parser.getgroup("msldap", "msldap test suite options")
    group.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Run tests that require a reachable, configured live LDAP/AD target.",
    )
    group.addoption(
        "--run-destructive",
        action="store_true",
        default=False,
        help="Run tests that create/modify/delete objects on the live target. "
        "Implies --run-live. Only use against a disposable lab!",
    )
    group.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run tests marked as slow.",
    )


def pytest_collection_modifyitems(config, items):
    # --run-destructive implies --run-live
    run_live = config.getoption("--run-live") or config.getoption("--run-destructive")

    enabled = {
        "live": run_live,
        "destructive": config.getoption("--run-destructive"),
        "slow": config.getoption("--run-slow"),
    }

    for item in items:
        for marker, flag in _OPT_IN_MARKERS:
            if marker in item.keywords and not enabled[marker]:
                item.add_marker(
                    pytest.mark.skip(
                        reason="requires %s opt-in flag" % flag
                    )
                )
