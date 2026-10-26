"""Trusted client metadata for the independently assembled read-only agent."""

from decepticon_core.registry.roles import RoleSpec

# AutoBot owns its middleware stack. This declares the admission purpose;
# it does not install Decepticon's execution middleware or grant tool access.
ROLE_SPEC = RoleSpec(name="autobot", slots=frozenset(), purpose="observation")
