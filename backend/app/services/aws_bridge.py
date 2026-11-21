"""GARUDA v5 AWS Edge-to-Cloud Telemetry Bridge.
- Converts local LAN alerts into official AWS Security Finding Format (ASFF 2018-10-08).
- Ingests & analyzes standard AWS VPC Flow Logs for cloud/hybrid threat visibility.
- Supports optional boto3 dispatch (Security Hub / EventBridge / SNS) with zero-cost dry-run default.
"""

import os
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .rule_updater import rule_manager

SAMPLE_VPC_FLOW_LOGS = """2 123456789012 eni-0a1b2c3d4e5f60001 198.51.100.42 10.0.1.25 51234 22 6 4 240 1763710001 1763710010 REJECT OK
2 123456789012 eni-0a1b2c3d4e5f60001 198.51.100.42 10.0.1.25 51235 23 6 4 240 1763710002 1763710011 REJECT OK
2 123456789012 eni-0a1b2c3d4e5f60001 198.51.100.42 10.0.1.25 51236 3389 6 4 240 1763710003 1763710012 REJECT OK
2 123456789012 eni-0a1b2c3d4e5f60001 198.51.100.42 10.0.1.25 51237 4444 6 4 240 1763710004 1763710013 REJECT OK
2 123456789012 eni-0a1b2c3d4e5f60001 198.51.100.42 10.0.1.25 51238 5555 6 4 240 1763710005 1763710014 REJECT OK
2 123456789012 eni-0a1b2c3d4e5f60001 10.0.1.25 203.0.113.99 49152 4444 6 1250 18500000 1763710015 1763710045 ACCEPT OK
2 123456789012 eni-0a1b2c3d4e5f60001 10.0.1.25 52.94.236.248 49200 443 6 18 14200 1763710020 1763710028 ACCEPT OK"""


def _map_severity_to_asff(sev: str) -> Dict[str, Any]:
    s = (sev or "info").lower()
    if s == "critical":
        return {"Label": "CRITICAL", "Normalized": 90}
    if s in ("high", "warning"):
        return {"Label": "HIGH", "Normalized": 70}
    if s == "medium":
        return {"Label": "MEDIUM", "Normalized": 45}
    return {"Label": "INFORMATIONAL", "Normalized": 10}


def to_aws_security_hub_asff(
    alert: Dict[str, Any],
    aws_account_id: Optional[str] = None,
    aws_region: Optional[str] = None,
) -> Dict[str, Any]:
    """Format a GARUDA alert dictionary into official AWS Security Finding Format (ASFF)."""
    account_id = aws_account_id or os.getenv("AWS_ACCOUNT_ID", "123456789012")
    region = aws_region or os.getenv("AWS_REGION", "ap-south-1")
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    finding_id = f"garuda-{alert.get('id', uuid.uuid4().hex[:12])}"
    rel_ip = alert.get("related_ip") or "127.0.0.1"
    rel_mac = alert.get("related_mac") or "00:00:00:00:00:00"

    return {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
        "GeneratorId": "garuda-v5-edge-sensor",
        "AwsAccountId": account_id,
        "Types": [f"TTPs/Network/{alert.get('attack_type', 'anomaly')}"],
        "CreatedAt": now_iso,
        "UpdatedAt": now_iso,
        "Severity": _map_severity_to_asff(alert.get("severity", "warning")),
        "Title": alert.get("title", "GARUDA Network Security Finding"),
        "Description": alert.get("plain_explanation", "Suspicious network activity detected by GARUDA edge sensor."),
        "Remediation": {
            "Recommendation": {
                "Text": alert.get("what_to_do", "Inspect the flagged host and isolate if unauthorized.")
            }
        },
        "Resources": [
            {
                "Type": "Other",
                "Id": f"lan-host:{rel_ip}",
                "Details": {
                    "Other": {
                        "IpAddress": str(rel_ip),
                        "MacAddress": str(rel_mac),
                        "Category": str(alert.get("category", "active_attack")),
                    }
                },
            }
        ],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
    }


def parse_vpc_flow_logs(raw_logs: str) -> Dict[str, Any]:
    """Parse standard AWS VPC Flow Logs (v2) and detect rejected port sweeps & suspicious egress spikes."""
    suspicious_ports = set(int(p) for p in rule_manager.rules.get("vpc_suspicious_ports", [22, 23, 3389, 4444, 5555]))
    parsed_count = 0
    total_packets = 0
    total_bytes = 0
    rejected_ports_by_src: Dict[str, set] = defaultdict(set)
    findings: List[Dict[str, Any]] = []

    for line in (raw_logs or "").splitlines():
        parts = line.strip().split()
        if len(parts) < 14 or parts[0] == "version":
            continue
        try:
            src_ip, dst_ip = parts[3], parts[4]
            dst_port = int(parts[6])
            packets = int(parts[8])
            byte_count = int(parts[9])
            action = parts[12].upper()
        except ValueError:
            continue

        parsed_count += 1
        total_packets += packets
        total_bytes += byte_count

        if action == "REJECT":
            rejected_ports_by_src[src_ip].add(dst_port)
        elif action == "ACCEPT" and (dst_port in suspicious_ports or byte_count >= 10_000_000):
            findings.append({
                "severity": "critical" if byte_count >= 10_000_000 else "warning",
                "attack_type": "vpc_suspicious_egress",
                "title": f"Suspicious AWS VPC Traffic to Port {dst_port} ({round(byte_count / 1_000_000, 2)} MB)",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "bytes": byte_count,
                "plain_explanation": (
                    f"Host {src_ip} transferred {byte_count:,} bytes to {dst_ip}:{dst_port} (ACCEPT). "
                    "High-volume transfers or C2-associated ports in VPC Flow Logs indicate potential exfiltration."
                ),
            })

    for src_ip, ports in rejected_ports_by_src.items():
        if len(ports) >= 4:
            findings.append({
                "severity": "high",
                "attack_type": "vpc_rejected_port_sweep",
                "title": f"External Port Sweep Blocked by VPC Security Group ({src_ip})",
                "src_ip": src_ip,
                "dst_ip": "VPC ENI",
                "dst_port": sorted(ports)[0],
                "ports_probed": sorted(ports),
                "plain_explanation": (
                    f"Source {src_ip} probed {len(ports)} distinct ports ({', '.join(map(str, sorted(ports)))}) "
                    "and was REJECTED by AWS Security Groups / NACLs."
                ),
            })

    return {
        "records_parsed": parsed_count,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "findings_count": len(findings),
        "findings": findings,
    }


def dispatch_aws_finding(asff_finding: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Optionally push an ASFF finding to AWS Security Hub via boto3; defaults to zero-cost dry-run."""
    if dry_run or not os.getenv("AWS_ACCESS_KEY_ID"):
        return {
            "dispatched": False,
            "mode": "dry_run_preview",
            "message": "Generated valid AWS Security Hub ASFF payload (Rs.0 dry-run mode; set AWS_ACCESS_KEY_ID + dry_run=False for live push).",
            "finding": asff_finding,
        }
    try:
        import boto3  # type: ignore
        client = boto3.client("securityhub", region_name=os.getenv("AWS_REGION", "ap-south-1"))
        resp = client.batch_import_findings(Findings=[asff_finding])
        return {
            "dispatched": True,
            "mode": "live_security_hub",
            "failed_count": resp.get("FailedCount", 0),
            "success_count": resp.get("SuccessCount", 0),
            "finding": asff_finding,
        }
    except Exception as exc:
        return {
            "dispatched": False,
            "mode": "fallback_preview",
            "message": f"Live AWS push skipped ({exc}); ASFF payload ready for manual import.",
            "finding": asff_finding,
        }
