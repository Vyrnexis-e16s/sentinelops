"""Build a Cypher script from stored TTP rows and edges (offline; no Neo4j driver)."""
from __future__ import annotations

from app.modules.vapt.models import VaptGraphEdge, VaptTtpMemory


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


def build_cypher_export(
    *,
    ttps: list[VaptTtpMemory],
    edges: list[VaptGraphEdge],
) -> tuple[str, int, int]:
    """Return (cypher_text, node_count, edge_count)."""
    lines: list[str] = [
        "// SentinelOps VAPT export — analyst-owned TTP notes and edges.",
        "// Paste into Neo4j Browser or `cypher-shell -f`. Not executed by the API.",
        "",
    ]
    node_ids: set[str] = set()
    for r in ttps:
        node_ids.add(r.technique_id.strip())
    for e in edges:
        node_ids.add(e.from_technique_id.strip())
        node_ids.add(e.to_technique_id.strip())

    label_by_id: dict[str, str] = {r.technique_id.strip(): r.name for r in ttps if r.name}

    for tid in sorted(node_ids):
        name = label_by_id.get(tid, tid)
        lines.append(f"MERGE (n:TTP {{technique_id: '{_esc(tid)}'}}) SET n.name = '{_esc(name)}';")

    lines.append("")

    for e in edges:
        rel = _esc(e.relation.strip() or "related")
        note = _esc((e.note or "")[:2000])
        fa, ta = e.from_technique_id.strip(), e.to_technique_id.strip()
        lines.append(
            f"MATCH (a:TTP {{technique_id: '{_esc(fa)}'}}), (b:TTP {{technique_id: '{_esc(ta)}'}}) "
            f"MERGE (a)-[r:RELATED {{kind: '{rel}', note: '{note}'}}]->(b);"
        )

    cypher = "\n".join(lines) + "\n"
    return cypher, len(node_ids), len(edges)
