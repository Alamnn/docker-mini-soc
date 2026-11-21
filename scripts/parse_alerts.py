#!/usr/bin/env python3
"""Parses Cowrie JSON logs and Suricata eve.json logs into a Markdown SOC alert summary table."""
import argparse
import json
from collections import Counter
from pathlib import Path

MITRE_MAP = {
    "cowrie.login.failed": ("100501 / 100502", "HIGH", "T1110.001", "SSH Brute Force (Password Guessing)"),
    "cowrie.login.success": ("100503", "HIGH", "T1021.004", "Valid Account / Honeypot SSH Login"),
    "cowrie.command.input": ("100504", "CRITICAL", "T1059.004", "Post-Login Unix Shell Command Execution"),
    "suricata.alert": ("100505", "HIGH", "T1046", "Suricata IDS Network Discovery / Exploit Alert"),
}


def parse_logs(cowrie_path: Path, suricata_path: Path) -> tuple[list[dict], Counter]:
    alerts = []
    ip_counts: Counter = Counter()

    if cowrie_path.exists():
        for line in cowrie_path.read_text().splitlines():
            if not line.strip():
                continue
            ev = json.loads(line)
            eid = ev.get("eventid", "")
            src = ev.get("src_ip", "unknown")
            ip_counts[src] += 1
            if eid in MITRE_MAP:
                rid, sev, mitre, desc = MITRE_MAP[eid]
                detail = ev.get("input") or f"user={ev.get('username','root')} password={ev.get('password','***')}"
                alerts.append({
                    "timestamp": ev.get("timestamp", ""),
                    "source": "Cowrie",
                    "rule_id": rid,
                    "severity": sev,
                    "mitre": mitre,
                    "src_ip": src,
                    "description": f"{desc}: `{detail}`",
                })

    if suricata_path.exists():
        for line in suricata_path.read_text().splitlines():
            if not line.strip():
                continue
            ev = json.loads(line)
            if ev.get("event_type") == "alert":
                src = ev.get("src_ip", "unknown")
                ip_counts[src] += 1
                rid, sev, mitre, _ = MITRE_MAP["suricata.alert"]
                sig = ev.get("alert", {}).get("signature", "Suricata Alert")
                dest = f"{ev.get('dest_ip', '')}:{ev.get('dest_port', '')}"
                alerts.append({
                    "timestamp": ev.get("timestamp", ""),
                    "source": "Suricata",
                    "rule_id": rid,
                    "severity": sev,
                    "mitre": mitre,
                    "src_ip": src,
                    "description": f"`{sig}` -> `{dest}`",
                })

    return alerts, ip_counts


def build_markdown(alerts: list[dict], ip_counts: Counter) -> str:
    rule_counts = Counter((a["rule_id"], a["severity"], a["mitre"], a["source"]) for a in alerts)
    lines = [
        "# Mini-SOC Triggered Alerts & Threat Telemetry Summary",
        "",
        "## 1. Triggered Custom Rules Summary",
        "",
        "| Wazuh Rule ID | Source Sensor | Severity | MITRE ATT&CK | Event Count |",
        "|---|---|---|---|---|",
    ]
    for (rid, sev, mitre, src), cnt in sorted(rule_counts.items()):
        lines.append(f"| `{rid}` | {src} | **{sev}** | `{mitre}` | {cnt} |")

    lines.extend([
        "",
        "## 2. Top Attacking Source IPs",
        "",
        "| Rank | Source IP | Total Malicious Events |",
        "|---|---|---|",
    ])
    for idx, (ip, cnt) in enumerate(ip_counts.most_common(10), 1):
        lines.append(f"| {idx} | `{ip}` | {cnt} |")

    lines.extend([
        "",
        "## 3. Detailed Alert Timeline",
        "",
        "| Timestamp | Sensor | Rule ID | Severity | MITRE | Source IP | Evidence / Payload |",
        "|---|---|---|---|---|---|---|",
    ])
    for a in alerts:
        lines.append(
            f"| `{a['timestamp']}` | {a['source']} | `{a['rule_id']}` | **{a['severity']}** | `{a['mitre']}` | `{a['src_ip']}` | {a['description']} |"
        )
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cowrie", default="logs/cowrie/cowrie.json")
    ap.add_argument("--suricata", default="logs/suricata/eve.json")
    ap.add_argument("--out", default="reports/alert_summary.md")
    args = ap.parse_args()

    alerts, ips = parse_logs(Path(args.cowrie), Path(args.suricata))
    md = build_markdown(alerts, ips)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md)
    print(md)


if __name__ == "__main__":
    main()
