import json
from collections import Counter
from pathlib import Path

def load_alerts(path=None):
    if path is None:
        path = Path(__file__).resolve().parent.parent / "Alerts.json"
    else:
        path = Path(path)
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
    for ip, count in by_ip.most_common(top_n):
        lines.append(f"{ip}: {count}")
    return "\n".join(lines)

def main():
    try:
        alerts = load_alerts()
    except FileNotFoundError:
        alerts_path = Path(__file__).resolve().parent.parent / "Alerts.json"
        print(f"Alerts file not found: {alerts_path}\nGenerate alerts by running IDSCore or placing Alerts.json at that location.")
        return

    total, by_rule, by_ip = summarize(alerts)
    report = format_text_report(total, by_rule, by_ip)
    print(report)


if __name__ == "__main__":
    main()