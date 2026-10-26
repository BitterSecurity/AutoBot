"""Event-store backend registry — pick a backend by name, install only it.

Backends are **independently installable** (redesign §5). The core never
force-installs every backend: each is selected at runtime by name and brings
only its own optional dependency. In-tree backends (``opensearch``) resolve
from a built-in map; external backends (e.g. a future ``autobot-store-clickhouse``
package) register themselves under the ``decepticon.event_stores`` entry-point
group and are discovered when — and only when — pip-installed.

    from autobot.stores import get_event_store
    store = get_event_store("opensearch", hosts="http://127.0.0.1:9200")

No "install everything" bundle is required: ``decepticon[opensearch]`` pulls
only ``opensearch-py``; a ClickHouse user installs a separate package instead.
"""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from decepticon_core.protocols.event_store import EventStoreProtocol

EVENT_STORES_GROUP = "decepticon.event_stores"


def _builtin_factories() -> dict[str, Any]:
    # Imported here (not at module load) so the base install never imports a
    # backend's optional dependency unless that backend is actually requested.
    from autobot.stores.opensearch_store import OpenSearchEventStore

    return {"opensearch": OpenSearchEventStore}


def available_backends() -> list[str]:
    """Names resolvable right now — built-ins plus pip-installed plugins."""
    names = set(_builtin_factories())
    for ep in entry_points(group=EVENT_STORES_GROUP):
        names.add(ep.name)
    return sorted(names)


def get_event_store(backend: str, /, **config: Any) -> EventStoreProtocol:
    """Construct the named EventStore backend.

    Resolution order: in-tree built-ins first, then ``decepticon.event_stores``
    entry-points (external, separately-installed packages). Raises ``KeyError``
    with the available names if the backend is unknown — which usually means
    its package is not installed.
    """
    factory = _builtin_factories().get(backend)
    if factory is None:
        for ep in entry_points(group=EVENT_STORES_GROUP):
            if ep.name == backend:
                factory = ep.load()
                break
    if factory is None:
        raise KeyError(
            f"unknown event-store backend {backend!r}; "
            f"available: {available_backends()} "
            f"(install the backend's package, e.g. `pip install decepticon[opensearch]`)"
        )
    return factory(**config)
