import json
from collections import Counter

def load_alerts(path="Alerts.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def summarize(alerts):
    total = len(alerts)
    by_rule = Counter(a.get("rule_name") or "UNKNOWN" for a in alerts)
    by_ip = Counter(a.get("source_ip") or "UNKNOWN" for a in alerts)
    return total, by_rule, by_ip

def format_text_report(total, by_rule, by_ip, top_n=5):
    lines = []
    lines.append("IDS ALERT REPORT")
    lines.append("----------------")
    lines.append(f"Total Alerts: {total}")
    lines.append("")
    for rule, count in by_rule.most_common():
        lines.append(f"{rule}: {count}")
    lines.append("")
    lines.append("Top Attacker IPs:")
    for ip, _ in by_ip.most_common(top_n):
        lines.append(ip)
    return "\n".join(lines)

def main():
    alerts = load_alerts("Alerts.json")
    total, by_rule, by_ip = summarize(alerts)
    report = format_text_report(total, by_rule, by_ip)
    print(report)