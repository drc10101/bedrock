"""
Mesh router — capability-scope-aware path calculation.

When a node is quarantined, the router immediately recalculates paths.
Medical-scope nodes never relay transaction data, even during recovery.
Alternate routes must exist before they're needed.

The router uses BFS for shortest-path and a modified BFS that excludes
specific nodes for alternate paths. Capability scope filtering ensures
data only flows through nodes authorized to see it.

Trade Secret — InFill Systems, LLC.
"""

from collections import deque
from typing import List, Optional, Dict, Set

from bedrock.identity.node import Node, NodeState
from bedrock.identity.capabilities import CapabilityScope, DataCategory


class MeshRouter:
    """Calculates routing paths through the mesh, respecting capability scopes.

    Key rules:
    1. A node can only relay data within its capability scope
    2. A node can only route traffic if it's in ACTIVE or SUSPECT state
    3. A HEALING node can relay (forward) but cannot decrypt
    4. Every path must have at least min_alternate_routes alternatives
    5. Quarantined and REVOKED nodes are excluded from all routing
    """

    def __init__(self):
        self._topology: Dict[str, Set[str]] = {}  # node_id -> {neighbor_ids}
        self._scopes: Dict[str, CapabilityScope] = {}  # node_id -> scope

    def register_neighbor(self, node_id: str, neighbor_id: str) -> None:
        """Register a neighbor relationship in the topology.

        Bidirectional: both directions are added.
        """
        if node_id not in self._topology:
            self._topology[node_id] = set()
        if neighbor_id not in self._topology:
            self._topology[neighbor_id] = set()
        self._topology[node_id].add(neighbor_id)
        self._topology[neighbor_id].add(node_id)

    def remove_neighbor(self, node_id: str, neighbor_id: str) -> None:
        """Remove a neighbor relationship (e.g., node quarantined).

        Bidirectional: both directions are removed.
        """
        if node_id in self._topology:
            self._topology[node_id].discard(neighbor_id)
        if neighbor_id in self._topology:
            self._topology[neighbor_id].discard(node_id)

    def register_scope(self, node_id: str, scope: CapabilityScope) -> None:
        """Register a capability scope for a node."""
        self._scopes[node_id] = scope

    def _can_relay(self, node_id: str, data_categories: List[DataCategory],
                   nodes: Dict[str, Node]) -> bool:
        """Check if a node can relay data for the given categories.

        A node can relay if:
        1. It exists in the node map
        2. It is in ACTIVE, SUSPECT, or HEALING state
        3. Its capability scope covers ALL required data categories
        """
        if node_id not in nodes:
            return False

        node = nodes[node_id]
        # HEALING nodes can relay but not decrypt (they can forward traffic)
        if node.state not in (NodeState.ACTIVE, NodeState.SUSPECT, NodeState.HEALING):
            return False

        # Check capability scope
        scope = self._scopes.get(node_id)
        if scope is None:
            # No scope registered = no categories = cannot relay
            return False

        return all(scope.can_access(cat) for cat in data_categories)

    def find_path(self, source_id: str, target_id: str,
                  data_categories: List[DataCategory],
                  nodes: Dict[str, Node]) -> List[str]:
        """Find a route from source to target for the given data categories.

        Uses BFS for shortest path. Only includes nodes whose capability
        scope covers ALL required categories. Skips QUARANTINED and REVOKED.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            data_categories: Required data categories for this traffic
            nodes: Map of node_id -> Node objects

        Returns:
            Ordered list of node IDs forming the path, or empty list if no path
        """
        if source_id == target_id:
            return [source_id]

        if source_id not in self._topology or target_id not in self._topology:
            return []

        # BFS
        queue = deque([[source_id]])
        visited = {source_id}

        while queue:
            path = queue.popleft()
            current = path[-1]

            for neighbor in self._topology.get(current, set()):
                if neighbor in visited:
                    continue

                # Target node always reachable (even if it can't relay further)
                if neighbor == target_id:
                    return path + [neighbor]

                # Check relay capability
                if not self._can_relay(neighbor, data_categories, nodes):
                    continue

                visited.add(neighbor)
                new_path = path + [neighbor]
                queue.append(new_path)

        return []  # No path found

    def find_alternate_path(self, source_id: str, target_id: str,
                           data_categories: List[DataCategory],
                           nodes: Dict[str, Node],
                           exclude_path: List[str]) -> List[str]:
        """Find an alternate route that avoids the given path's nodes.

        Used when a path fails or a node is quarantined.
        Excludes all intermediate nodes (not source/target) from
        the previous path.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            data_categories: Required data categories
            nodes: Map of node_id -> Node objects
            exclude_path: Previous path whose intermediate nodes to avoid

        Returns:
            Alternate path, or empty list if none found
        """
        if source_id == target_id:
            return [source_id]

        # Exclude intermediate nodes from previous path (keep source and target)
        excluded = set(exclude_path) - {source_id, target_id}

        if source_id not in self._topology or target_id not in self._topology:
            return []

        # BFS with exclusion set
        queue = deque([[source_id]])
        visited = {source_id} | excluded

        while queue:
            path = queue.popleft()
            current = path[-1]

            for neighbor in self._topology.get(current, set()):
                if neighbor in visited:
                    continue

                if neighbor == target_id:
                    return path + [neighbor]

                if not self._can_relay(neighbor, data_categories, nodes):
                    continue

                visited.add(neighbor)
                new_path = path + [neighbor]
                queue.append(new_path)

        return []  # No alternate path found

    def verify_redundancy(self, nodes: Dict[str, Node],
                          min_alternates: int = 1) -> Dict[str, int]:
        """Verify that every node has at least min_alternates alternate routes.

        Returns a dict of node_id -> number of alternate routes available.
        Nodes below the threshold should be flagged.
        """
        result: Dict[str, int] = {}
        node_ids = list(self._topology.keys())

        for source_id in node_ids:
            alternate_count = 0
            for target_id in node_ids:
                if source_id == target_id:
                    continue

                # Use the node's scope categories for the check
                scope = self._scopes.get(source_id)
                if scope is None:
                    continue

                # Find primary path
                primary = self.find_path(source_id, target_id,
                                        scope.categories, nodes)
                if not primary:
                    continue

                # Find alternate path
                alternate = self.find_alternate_path(source_id, target_id,
                                                     scope.categories, nodes,
                                                     primary)
                if alternate:
                    alternate_count += 1

            result[source_id] = alternate_count

        return result

    def get_topology(self) -> Dict[str, Set[str]]:
        """Return the current topology map."""
        return {k: set(v) for k, v in self._topology.items()}

    def get_neighbors(self, node_id: str) -> Set[str]:
        """Get the neighbors of a node."""
        return self._topology.get(node_id, set())