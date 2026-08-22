from collections import defaultdict


def reconstruct_story(host_windows: list) -> list:
    """
    Build a window-indexed event timeline for a single host.
    Input: list of enriched window records for one srcip, sorted by window index.
    Returns: list of {window, events} dicts.
    """
    timeline = []
    prev = {}

    for rec in host_windows:
        w      = rec['window']
        label  = f"W{w}"
        events = []

        # New peer contact
        npc = rec.get('new_peer_count', 0)
        if npc > 0:
            events.append(f"Contacted {npc} previously unseen host(s) "
                          f"(new_peer_ratio={rec.get('new_peer_ratio',0):.0%})")

        # Destination deviation crossed threshold
        dd = rec.get('dest_dev', 1)
        if dd > 2 and prev.get('dest_dev', 1) <= 2:
            events.append(f"Destination count exceeded baseline — now {dd:.1f}x above normal")
        elif dd > prev.get('dest_dev', 1) * 1.5 and dd > 2:
            events.append(f"Destination spread increased further to {dd:.1f}x baseline")

        # Port deviation
        pd_ = rec.get('port_dev', 1)
        if pd_ > 2 and prev.get('port_dev', 1) <= 2:
            events.append(f"Port diversity crossed threshold — {pd_:.1f}x above baseline")

        # Burst
        bd = rec.get('burst_dev', 1)
        if bd > 2 and prev.get('burst_dev', 1) <= 2:
            events.append(f"Connection burst detected — {bd:.1f}x normal rate")

        # Score threshold crossings
        score = rec.get('scan_score', 0)
        prev_score = prev.get('scan_score', 0)
        for threshold in [40, 60, 75, 90]:
            if score >= threshold > prev_score:
                events.append(f"Risk score crossed {threshold} → {score:.0f}")

        # Scan DNA
        dna = rec.get('scan_dna', 'Normal')
        prev_dna = prev.get('scan_dna', 'Normal')
        if dna != 'Normal' and dna != prev_dna:
            events.append(f"Classified as {dna} Scan")

        # Stage escalation
        stage = rec.get('threat_level', 1)
        prev_stage = prev.get('threat_level', 1)
        if stage > prev_stage:
            events.append(f"STAGE ESCALATED → {rec.get('threat_stage_label','')}")

        # Alert confirmed
        if rec.get('is_alert') and not prev.get('is_alert'):
            events.append(f"ALERT CONFIRMED — {rec.get('fp_guard_reason','')}")

        if not events:
            events.append("No significant deviation observed")

        timeline.append({'window': label, 'events': events, 'scan_score': score,
                         'threat_level': stage, 'scan_dna': dna})
        prev = rec

    return timeline


def build_all_stories(window_records: list) -> dict:
    """Group window records by host and reconstruct story for each."""
    host_windows = defaultdict(list)
    for rec in window_records:
        host_windows[rec['srcip']].append(rec)

    return {
        src: reconstruct_story(sorted(wins, key=lambda r: r['window']))
        for src, wins in host_windows.items()
    }
