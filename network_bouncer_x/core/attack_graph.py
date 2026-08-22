import numpy as np
from collections import defaultdict


def build_attack_graph(window_records: list, alert_threshold: float = 40.0) -> dict:
    """
    Build a directed communication graph from alert-level window records.
    Nodes  = source IPs that produced alerts
    Edges  = (srcip → dstip) communication where srcip was flagged

    Columns used: srcip, dstip (via unique_dsts count — actual dstips come
    from the raw window records enriched with contacted_peers field if available,
    otherwise we represent edges as srcip → peer_group).

    Returns:
      nodes : {srcip: {score, stage, scan_dna}}
      edges : [(src, dst, weight)]
      chains: list of propagation chains [A→B→C→D]
    """
    # Build adjacency from records that have peer info
    adjacency  = defaultdict(set)
    node_attrs = {}

    for rec in window_records:
        if rec.get('scan_score', 0) < alert_threshold:
            continue
        src   = rec['srcip']
        score = rec.get('scan_score', 0)
        stage = rec.get('threat_stage_label', 'Normal')
        dna   = rec.get('scan_dna', 'Normal')

        node_attrs[src] = {
            'score': max(node_attrs.get(src, {}).get('score', 0), score),
            'stage': stage,
            'scan_dna': dna,
        }

        # Use new_peers_list if available (added by time_window enrichment)
        for peer in rec.get('new_peers_list', []):
            adjacency[src].add(peer)

    edges = []
    for src, dsts in adjacency.items():
        for dst in dsts:
            w = node_attrs.get(src, {}).get('score', 0)
            edges.append((src, dst, round(w, 1)))

    # Detect recon chains: A→B where B is also a flagged scanner
    flagged = set(node_attrs.keys())
    chains  = _find_chains(adjacency, flagged)

    return {
        'nodes': node_attrs,
        'edges': edges,
        'chains': chains,
    }


def _find_chains(adjacency: dict, flagged: set, max_depth: int = 6) -> list:
    """
    Find propagation chains where flagged host A contacts flagged host B
    which also contacts flagged host C (lateral movement pattern).
    """
    chains = []
    visited_chains = set()

    def dfs(node, path):
        if len(path) > max_depth:
            return
        for neighbor in adjacency.get(node, []):
            if neighbor in flagged and neighbor not in path:
                new_path = path + [neighbor]
                key = tuple(new_path)
                if key not in visited_chains and len(new_path) >= 2:
                    visited_chains.add(key)
                    chains.append(new_path)
                dfs(neighbor, new_path)

    for start in flagged:
        dfs(start, [start])

    # Return longest chains first
    return sorted(chains, key=len, reverse=True)[:20]


def graph_summary(attack_graph: dict) -> dict:
    """Summarise attack graph for dashboard display."""
    nodes  = attack_graph['nodes']
    edges  = attack_graph['edges']
    chains = attack_graph['chains']
    return {
        'flagged_node_count': len(nodes),
        'edge_count':         len(edges),
        'chain_count':        len(chains),
        'longest_chain':      max((len(c) for c in chains), default=0),
        'chain_strings':      [' → '.join(c) for c in chains[:10]],
    }
