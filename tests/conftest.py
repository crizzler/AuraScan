"""Keep real host recovery and policy state outside offline test decisions."""

from functools import wraps
import pytest


@pytest.fixture(scope="session", autouse=True)
def isolated_host_runtime_and_default_policies(tmp_path_factory):
    # A real root-private /run/aurascan-recovery on the developer's host must
    # neither change these tests' runtime mode nor produce PermissionError on
    # Python 3.8. Runtime-specific tests still inject their own evidence/flags.
    from aurascan.core import agent, followup, recovery, recovery_cli
    from aurascan import setup_wizard

    private = tmp_path_factory.mktemp("inert-host-context")
    marker = private / "environment"
    patch = pytest.MonkeyPatch()
    patch.setattr(agent, "AGENT_RECOVERY_RUNTIME_MARKER", marker)
    patch.setattr(followup, "FOLLOWUP_RECOVERY_RUNTIME_MARKER", marker)
    patch.setattr(recovery, "RECOVERY_RUNTIME_MARKER", marker)
    patch.setattr(recovery_cli, "RECOVERY_RUNTIME_MARKER", marker)

    def private_default_reader(original):
        default = original.__defaults__[0]

        @wraps(original)
        def read(path=default, **kwargs):
            # Explicit fixture paths still exercise the real parser unchanged.
            return original(private / default.name if path == default else path, **kwargs)

        return read

    for name in ("read_agent_root_policy", "read_auto_repair_policy", "read_recovery_policy"):
        reader = private_default_reader(getattr(setup_wizard, name))
        patch.setattr(setup_wizard, name, reader)
        if name == "read_agent_root_policy":
            patch.setattr(agent, name, reader)
    try:
        yield
    finally:
        patch.undo()
