"""
Mesh router — capability-scope-aware path calculation.

When a node is quarantined, the router immediately recalculates paths.
Medical-scope nodes never relay transaction data, even during recovery.
Alternate routes must exist before they're needed.
"""

from typing import List, Optional, Dict
from bedrock.identity.node import Node, NodeState
from bedrock.identity.capabilities import CapabilityScope, DataCategory


class MeshRouter:
    """Calculates routing paths through the mesh, respecting capability scopes.

    Key rules:
    1. A node can only relay data within its capability scope
    2. A node can only route traffic if it's in ACTIVE or SUSPECT state
    3. A HEALING node can relay (forward) but cannot decrypt
    4. Every path must have at least min_alternate_routes alternatives
    5. Quarantined nodes are excluded from all routing calculations
    """

    def __init__(self, config=None):
        self._config = config
        self._topology: Dict[str, List[str]] = {}  # node_id -> [neighbor_ids]

    def register_neighbor(self, node_id: str, neighbor_id: str) -> None:
        """Register a neighbor relationship in the topology."""
        raise NotImplementedError("B-111: Self-Healing Mesh")

    def remove_neighbor(self, node_id: str, neighbor_id: str) -> None:
        """Remove a neighbor relationship (e.g., node quarantined)."""
        raise NotImplementedError("B-111: Self-Healing Mesh")

    def find_path(self, source_id: str, target_id: str,
                  data_categories: List[DataCategory],
                  nodes: Dict[str, Node]) -> List[str]:
        """Find a route from source to target for the given data categories.

        Only includes nodes whose capability scope covers ALL required categories.
        Skips QUARANTINED and REVOKED nodes.
        Returns an ordered list of node IDs forming the path.
        """
        raise NotImplementedError("B-111: Self-Healing Mesh")

    def find_alternate_path(self, source_id: str, target_id: str,
                           data_categories: List[DataCategory],
                           nodes: Dict[str, Node],
                           exclude_path: List[str]) -> List[str]:
        """Find an alternate route that avoids the given path's nodes.

        Used when a path fails or a node is quarantined.
        """
        raise NotImplementedError("B-111: Self-Healing Mesh")

    def verify_redundancy(self, nodes: Dict[str, Node],
                          min_alternates: int = 1) -> Dict[str, int]:
        """Verify that every node has at least min_alternates alternate routes.

        Returns a dict of node_id -> number of alternate routes available.
        Nodes below the threshold should be flagged.
        """
        raise NotImplementedError("B-111: Self-Healing Mesh")