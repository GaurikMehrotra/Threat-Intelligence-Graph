"""Understandable bounded graph algorithms. Connectivity is not attribution."""

from collections import deque
from datetime import datetime

from src.normalization.entities import ENTITY_TYPES
from src.schemas.models import RELATIONSHIPS
from src.storage.sqlite import GraphStore

MAX_DEPTH = 6
MAX_NODES = 1000
MAX_EDGES = 5000
MAX_SCAN = 20000


class GraphQueries:
    def __init__(self, store: GraphStore):
        self.store = store

    @staticmethod
    def _limits(depth, limit):
        if not 0 <= depth <= MAX_DEPTH or not 1 <= limit <= MAX_NODES:
            raise ValueError("depth must be 0..6 and node limit 1..1000")

    @staticmethod
    def _filters(entity_types, relationship_types, after, before):
        if entity_types and set(entity_types) - ENTITY_TYPES:
            raise ValueError("unsupported entity filter")
        if relationship_types and set(relationship_types) - RELATIONSHIPS.keys():
            raise ValueError("unsupported relationship filter")
        if any(t is not None and t.tzinfo is None for t in (after, before)):
            raise ValueError("time filters require timezone")
        if after and before and after > before:
            raise ValueError("invalid temporal filter interval")

    @staticmethod
    def _edge_matches(
        edge,
        relationship_types=None,
        after=None,
        before=None,
        include_unknown=True,
        include_inactive=False,
    ):
        if not include_inactive and edge.status in {"rejected", "superseded"}:
            return False
        if relationship_types and edge.relationship_type not in relationship_types:
            return False
        if (after or before) and not include_unknown and not (edge.valid_from or edge.valid_until):
            return False
        if after and edge.valid_until and edge.valid_until < after:
            return False
        if before and edge.valid_from and edge.valid_from > before:
            return False
        return True

    def neighborhood(
        self,
        node_id: str,
        depth=1,
        limit=100,
        entity_types=None,
        relationship_types=None,
        after: datetime | None = None,
        before: datetime | None = None,
        include_unknown=True,
        include_inactive=False,
    ):
        self._limits(depth, limit)
        self._filters(entity_types, relationship_types, after, before)
        root = self.store.get_node(node_id)
        nodes, edges = {node_id: root}, {}
        queue = deque([(node_id, 0)])
        scanned, truncated = 0, False
        while queue:
            current, level = queue.popleft()
            if level >= depth:
                continue
            candidates = self.store.incident(current, min(MAX_SCAN - scanned, MAX_EDGES) + 1)
            for edge in candidates:
                scanned += 1
                if scanned > MAX_SCAN or len(edges) >= MAX_EDGES:
                    truncated = True
                    queue.clear()
                    break
                if not self._edge_matches(
                    edge, relationship_types, after, before, include_unknown, include_inactive
                ):
                    continue
                other = (
                    edge.target_node_id if edge.source_node_id == current else edge.source_node_id
                )
                target = self.store.get_node(other)
                if entity_types and target.entity_type not in entity_types:
                    continue
                if other not in nodes:
                    if len(nodes) >= limit:
                        truncated = True
                        continue
                    nodes[other] = target
                    queue.append((other, level + 1))
                edges[edge.edge_id] = edge
            if len(candidates) > MAX_EDGES:
                truncated = True
        # Include edges between returned nodes only; all output IDs resolve locally.
        return {
            "nodes": [n.model_dump(mode="json") for n in nodes.values()],
            "edges": [e.model_dump(mode="json") for e in edges.values()],
            "truncated": truncated,
            "scanned_edges": scanned,
            "depth": depth,
            "interpretation": "Connectivity shows recorded claims, not common ownership or attribution.",
        }

    def path(self, source: str, target: str, depth=6, limit=1000, directed=False):
        self._limits(depth, limit)
        self.store.get_node(source)
        self.store.get_node(target)
        queue = deque([(source, 0)])
        parent = {source: None}
        via = {}
        scanned, truncated = 0, False
        while queue:
            current, level = queue.popleft()
            if current == target:
                result_nodes, result_edges = [], []
                while current is not None:
                    result_nodes.append(current)
                    if current in via:
                        result_edges.append(via[current])
                    current = parent[current]
                return {
                    "node_ids": result_nodes[::-1],
                    "edge_ids": result_edges[::-1],
                    "found": True,
                    "truncated": truncated,
                }
            if level >= depth:
                continue
            for edge in self.store.incident(current, MAX_SCAN - scanned + 1):
                scanned += 1
                if scanned > MAX_SCAN:
                    return {"node_ids": [], "edge_ids": [], "found": False, "truncated": True}
                if not self._edge_matches(edge) or directed and edge.source_node_id != current:
                    continue
                other = (
                    edge.target_node_id if edge.source_node_id == current else edge.source_node_id
                )
                if other in parent:
                    continue
                if len(parent) >= limit:
                    truncated = True
                    continue
                parent[other], via[other] = current, edge.edge_id
                queue.append((other, level + 1))
        return {
            "node_ids": [],
            "edge_ids": [],
            "found": False,
            "truncated": truncated,
            "note": "No path within the selected depth and resource limits.",
        }

    def shared_neighbors(self, node_ids: list[str], limit=100):
        if not 2 <= len(node_ids) <= 10:
            raise ValueError("select 2..10 entities")
        graphs = [self.neighborhood(n, 1, MAX_NODES) for n in node_ids]
        neighbors = [
            {n["node_id"] for n in g["nodes"]} - {root}
            for root, g in zip(node_ids, graphs, strict=True)
        ]
        shared = sorted(set.intersection(*neighbors) - set(node_ids))
        self._limits(1, limit)
        return {
            "nodes": [self.store.get_node(n).model_dump(mode="json") for n in shared[:limit]],
            "truncated": len(shared) > limit or any(g["truncated"] for g in graphs),
        }

    def shared_indicators(self, limit=100):
        self._limits(1, limit)
        # One entry per canonical indicator, distinct reports, not evidence repetitions.
        rows = self.store.shared_indicator_counts(limit + 1)
        return {
            "indicators": [
                {"node": self.store.get_node(r[0]).model_dump(mode="json"), "report_count": r[1]}
                for r in rows[:limit]
            ],
            "truncated": len(rows) > limit,
        }

    def related_techniques(self, node_id, depth=2, limit=100):
        graph = self.neighborhood(node_id, depth, limit)
        techniques = [n for n in graph["nodes"] if n["entity_type"] == "attack_technique"]
        return {
            "techniques": techniques,
            "truncated": graph["truncated"],
            "note": "Inspect mapping evidence; graph proximity is not itself an ATT&CK mapping.",
        }

    def summary(self, limit=1000):
        self._limits(1, limit)
        rows = self.store.scan_nodes(limit + 1)
        nodes = rows[:limit]
        identifiers = {n.node_id for n in nodes}
        adjacency = {n: set() for n in identifiers}
        degrees = {n: 0 for n in identifiers}
        edge_rows = self.store.scan_edges(MAX_SCAN + 1)
        for e in edge_rows[:MAX_SCAN]:
            if not self._edge_matches(e):
                continue
            for node in {e.source_node_id, e.target_node_id} & identifiers:
                degrees[node] += 1
            if e.source_node_id in identifiers and e.target_node_id in identifiers:
                adjacency[e.source_node_id].add(e.target_node_id)
                adjacency[e.target_node_id].add(e.source_node_id)
        components, visited = [], set()
        for node in sorted(identifiers):
            if node in visited:
                continue
            component, queue = [], deque([node])
            visited.add(node)
            while queue:
                current = queue.popleft()
                component.append(current)
                for neighbor in sorted(adjacency[current] - visited):
                    visited.add(neighbor)
                    queue.append(neighbor)
            components.append(component)
        return {
            "components": components,
            "degrees": degrees,
            "truncated": len(rows) > limit or len(edge_rows) > MAX_SCAN,
            "note": "Components are undirected claim connectivity. Degrees count claims, not independent actors.",
        }
