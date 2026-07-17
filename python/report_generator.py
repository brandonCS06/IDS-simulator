import argparse
import csv
import datetime
import json
import logging
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO, TypedDict


LOGGER = logging.getLogger(__name__)
UTC = datetime.timezone.utc


class Alert(TypedDict, total=False):
    timestamp: int
    rule_name: str
    severity: str
    source_ip: str
    target: str
    evidence: list[dict[str, Any]]


@dataclass(frozen=True)
class ReportSummary:
    total: int
    by_rule: Counter[str]
    by_ip: Counter[str]
    by_severity: Counter[str]
    by_target: Counter[str]
    by_time_window: Counter[str]


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def default_alerts_path() -> Path:
    return Path(__file__).resolve().parent.parent / "Alerts.json"


def load_alerts(path: str | Path | None = None) -> list[Alert]:
    if path is None:
        path = default_alerts_path()
    else:
        path = Path(path)
    with Path(path).open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Alerts file must contain a JSON array")
    return [coerce_alert(item, index) for index, item in enumerate(data)]


def coerce_alert(item: Any, index: int) -> Alert:
    if not isinstance(item, dict):
        raise ValueError(f"Alert at index {index} is not a JSON object")
    return item


def summarize(alerts: list[Alert]):
    """
    Backwards-compatible summary used by the original text report.
    """
    summary = build_summary(alerts)
    return summary.total, summary.by_rule, summary.by_ip


def build_summary(alerts: list[Alert], window_minutes: int = 5) -> ReportSummary:
    total = len(alerts)
    by_rule = Counter(alert.get("rule_name") or "UNKNOWN" for alert in alerts)
    by_ip = Counter(alert.get("source_ip") or "UNKNOWN" for alert in alerts)
    by_severity = Counter((alert.get("severity") or "UNKNOWN").lower() for alert in alerts)
    by_target = Counter(extract_target(alert) for alert in alerts)
    by_time_window = Counter(time_window(alert.get("timestamp"), window_minutes) for alert in alerts)
    return ReportSummary(total, by_rule, by_ip, by_severity, by_target, by_time_window)


def extract_target(alert: Alert) -> str:
    target = alert.get("target")
    if target:
        return str(target)
    evidence = alert.get("evidence") or []
    if evidence and isinstance(evidence[0], dict):
        evidence_target = evidence[0].get("target")
        if evidence_target:
            return str(evidence_target)
    return "UNKNOWN"


def time_window(timestamp: Any, window_minutes: int) -> str:
    if timestamp in (None, ""):
        return "UNKNOWN"
    try:
        epoch_ms = int(timestamp)
    except (TypeError, ValueError):
        return "UNKNOWN"
    window_ms = max(window_minutes, 1) * 60 * 1000
    bucket_start = epoch_ms - (epoch_ms % window_ms)
    dt = datetime.datetime.fromtimestamp(bucket_start / 1000, tz=UTC)
    return dt.isoformat().replace("+00:00", "Z")


def format_text_report(
    total,
    by_rule,
    by_ip,
    top_n: int = 5,
    by_severity: Counter[str] | None = None,
    by_target: Counter[str] | None = None,
    by_time_window: Counter[str] | None = None,
) -> str:
    lines: list[str] = []
    lines.append("IDS ALERT REPORT")
    lines.append("----------------")
    lines.append(f"Total Alerts: {total}")
    lines.append("")
    lines.append("Alerts by Rule:")
    for rule, count in by_rule.most_common():
        lines.append(f"{rule}: {count}")

    if by_severity is not None:
        lines.append("")
        lines.append("Alerts by Severity:")
        for severity, count in by_severity.most_common():
            lines.append(f"{severity}: {count}")

    lines.append("")
    lines.append("Top Attacker IPs:")
    for ip, count in by_ip.most_common(top_n):
        lines.append(f"{ip}: {count}")

    if by_target is not None:
        lines.append("")
        lines.append("Top Targets:")
        for target, count in by_target.most_common(top_n):
            lines.append(f"{target}: {count}")

    if by_time_window is not None:
        lines.append("")
        lines.append("Alerts by Time Window:")
        for window, count in sorted(by_time_window.items()):
            lines.append(f"{window}: {count}")

    return "\n".join(lines)


def summary_to_jsonable(summary: ReportSummary, top_n: int = 5) -> dict[str, Any]:
    return {
        "total": summary.total,
        "by_rule": dict(summary.by_rule.most_common()),
        "by_severity": dict(summary.by_severity.most_common()),
        "top_source_ips": dict(summary.by_ip.most_common(top_n)),
        "top_targets": dict(summary.by_target.most_common(top_n)),
        "by_time_window": dict(sorted(summary.by_time_window.items())),
    }


def write_json_report(summary: ReportSummary, stream: TextIO, top_n: int = 5) -> None:
    json.dump(summary_to_jsonable(summary, top_n), stream, indent=4)
    stream.write("\n")


def write_csv_report(summary: ReportSummary, stream: TextIO, top_n: int = 5) -> None:
    writer = csv.DictWriter(stream, fieldnames=["category", "value", "count"])
    writer.writeheader()
    write_counter_rows(writer, "rule", summary.by_rule)
    write_counter_rows(writer, "severity", summary.by_severity)
    write_counter_rows(writer, "source_ip", Counter(dict(summary.by_ip.most_common(top_n))))
    write_counter_rows(writer, "target", Counter(dict(summary.by_target.most_common(top_n))))
    write_counter_rows(writer, "time_window", Counter(dict(sorted(summary.by_time_window.items()))))


def write_counter_rows(writer: csv.DictWriter, category: str, counter: Counter[str]) -> None:
    for value, count in counter.items():
        writer.writerow({"category": category, "value": value, "count": count})


def write_report(summary: ReportSummary, output_format: str, output: str | None, top_n: int) -> None:
    if output is None:
        stream = sys.stdout
        close_stream = False
    else:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stream = output_path.open("w", encoding="utf-8", newline="")
        close_stream = True

    try:
        if output_format == "text":
            report = format_text_report(
                summary.total,
                summary.by_rule,
                summary.by_ip,
                top_n=top_n,
                by_severity=summary.by_severity,
                by_target=summary.by_target,
                by_time_window=summary.by_time_window,
            )
            print(report, file=stream)
        elif output_format == "json":
            write_json_report(summary, stream, top_n)
        elif output_format == "csv":
            write_csv_report(summary, stream, top_n)
        else:
            raise ValueError(f"unsupported report format: {output_format}")
    finally:
        if close_stream:
            stream.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate an IDS alert summary report.")
    parser.add_argument("--input", default=str(default_alerts_path()), help="Path to Alerts.json.")
    parser.add_argument("--output", help="Optional report output path. Defaults to stdout.")
    parser.add_argument("--format", choices=["text", "json", "csv"], default="text", help="Report format.")
    parser.add_argument("--top_n", type=int, default=5, help="Number of top IPs and targets to include.")
    parser.add_argument("--window_minutes", type=int, default=5, help="Time bucket size for alert counts.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)
    try:
        alerts = load_alerts(args.input)
        summary = build_summary(alerts, window_minutes=args.window_minutes)
        write_report(summary, args.format, args.output, args.top_n)
    except FileNotFoundError:
        LOGGER.error(
            "Alerts file not found: %s. Generate alerts by running IDSCore or placing Alerts.json there.",
            args.input,
        )
        return 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        LOGGER.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
