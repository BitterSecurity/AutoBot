"""Exercise installed plugin metadata consumed by client admission."""

from decepticon_core.plugin_loader import load_plugin_role_specs


def test_installed_autobot_declares_observation_without_execution_middleware():
    roles = {spec.name: spec for spec in load_plugin_role_specs()}
    assert roles["autobot"].purpose == "observation"
    assert not roles["autobot"].slots
