"""Event store backends implementing EventStoreProtocol (redesign §5).

Default substrate: OpenSearch (``OpenSearchEventStore``). Backends are
swapped behind the protocol so detection and the agent never change.
"""

from __future__ import annotations

from autobot.stores.opensearch_store import OpenSearchEventStore
from autobot.stores.registry import (
    available_backends,
    get_event_store,
)

__all__ = ["OpenSearchEventStore", "available_backends", "get_event_store"]
