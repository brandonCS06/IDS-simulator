import argparse
import csv
import datetime
import ipaddress
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, TypedDict


"""
Utility CLI for converting raw log files into a normalized `Events.json`
payload that the Java network IDS engine can consume. It accepts normalized JSON arrays,
generic JSON objects/arrays, JSON Lines, and CSV logs, coercing them into a
consistent Event schema and validating required fields before writing.
"""


LOGGER = logging.getLogger(__name__)
UTC = datetime.timezone.utc

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "Events.json"

REQUIRED_KEYS = ("timestamp", "source_ip", "user", "action", "target", "metadata")


class Event(TypedDict):
    timestamp: int
    source_ip: str
    user: str
    action: str
    target: str
    metadata: dict[str, Any]


KEY_ALIASES = {
    "timestamp": ("timestamp", "time", "ts", "unix", "date"),
    "source_ip": ("source_ip", "ip", "source_ip_address", "client_ip"),
    "user": ("user", "username", "uid"),
    "action": ("action", "event", "event_type", "type"),
    "target": ("target", "service", "resource", "target_service"),
    "metadata": ("metadata", "meta", "extra", "details"),
}


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse raw log files into Events.json for the Java network IDS engine."
    )
    parser.add_argument("--input", required=True, help="Path to raw log file.")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"Output path for Events.json (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "events-json", "jsonl", "csv"],
        default="json",
        help="Input format: json, events-json, jsonl, or csv.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()
    configure_logging(args.verbose)

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()

    try:
        raw_records = load_raw_records(str(input_path), args.format)
        events = normalize_records(raw_records, args.format)
        write_events(events, str(output_path))
    except FileNotFoundError:
        LOGGER.error("Input file not found: %s", input_path)
        return 1
    except json.JSONDecodeError as exc:
        LOGGER.error("Invalid JSON in %s: %s", input_path, exc)
        return 1
    except (OSError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1

    LOGGER.info("Wrote %d event(s) to %s", len(events), output_path)
    return 0


def load_raw_records(path: str, fmt: str) -> list[dict[str, Any]]:
    """
    Load raw records from disk based on the declared input format.

    For `events-json`, this expects a top-level JSON array of normalized
    event-like objects. Generic `json` accepts a single object or array.
    JSON Lines reads one JSON object per line. CSV reads rows as dictionaries.
    """
    if fmt in {"json", "events-json"}:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if fmt == "events-json" and not isinstance(data, list):
            raise ValueError("events-json format expects a top-level JSON array")
        if isinstance(data, list):
            return _ensure_record_list(data)
        if isinstance(data, dict):
            return [data]
        raise ValueError("Input JSON must be an array or object")

    if fmt == "jsonl":
        records: list[dict[str, Any]] = []
        with open(path, encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError(f"JSONL line {line_number} is not a JSON object")
                records.append(record)
        return records

    if fmt == "csv":
        with open(path, encoding="utf-8", newline="") as f:
            return [dict(row) for row in csv.DictReader(f)]

    raise ValueError(f"unsupported input format: {fmt}")


def _ensure_record_list(data: list[Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Record at index {i} is not a JSON object")
        records.append(item)
    return records


def normalize_records(raw_records: list[dict[str, Any]], fmt: str) -> list[Event]:
    events: list[Event] = []
    for i, raw in enumerate(raw_records):
        try:
            event = normalize_record(raw, fmt)
            validate_event(event)
            events.append(event)
        except ValueError as exc:
            raise ValueError(f"Record at index {i}: {exc}") from exc
    return events


def write_events(events: list[Event], path: str) -> None:
    """
    Persist normalized events to disk as pretty-printed JSON.

    The Java side expects a JSON array, so parser output intentionally remains
    JSON even when the parser ingests CSV or JSON Lines.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=4)
        f.write("\n")


def normalize_record(raw: dict[str, Any], fmt: str) -> Event:
    """
    Map a single raw input record into the canonical Event schema
    (`timestamp`, `source_ip`, `user`, `action`, `target`, `metadata`).
    """
    if fmt == "events-json":
        return _normalize_event_like(raw)
    return _normalize_generic(raw)


def _normalize_event_like(raw: dict[str, Any]) -> Event:
    out: dict[str, Any] = {}
    timestamp = raw.get("timestamp")
    if timestamp is None:
        raise ValueError("missing required field: timestamp")
    out["timestamp"] = coerce_timestamp(timestamp)

    for key in ("source_ip", "user", "action", "target"):
        val = raw.get(key)
        if val is None:
            raise ValueError(f"missing required field: {key}")
        out[key] = str(val).strip()

    out["metadata"] = coerce_metadata(raw.get("metadata"))
    _merge_extra_metadata(out["metadata"], raw, set(REQUIRED_KEYS))
    return out  # type: ignore[return-value]


def _normalize_generic(raw: dict[str, Any]) -> Event:
    out: dict[str, Any] = {}

    timestamp = _first_value(raw, KEY_ALIASES["timestamp"])
    if timestamp is None:
        raise ValueError("missing required field: timestamp (or time/ts/unix/date)")
    out["timestamp"] = coerce_timestamp(timestamp)

    for key, aliases in (
        ("source_ip", KEY_ALIASES["source_ip"]),
        ("user", KEY_ALIASES["user"]),
        ("action", KEY_ALIASES["action"]),
        ("target", KEY_ALIASES["target"]),
    ):
        val = _first_value(raw, aliases)
        if val is None:
            raise ValueError(f"missing required field: {key}")
        out[key] = str(val).strip()

    out["metadata"] = coerce_metadata(_first_value(raw, KEY_ALIASES["metadata"]))

    consumed: set[str] = set()
    for aliases in KEY_ALIASES.values():
        consumed.update(aliases)
    consumed.update(REQUIRED_KEYS)
    _merge_extra_metadata(out["metadata"], raw, consumed)
    return out  # type: ignore[return-value]


def coerce_timestamp(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("timestamp must be an integer, numeric string, or ISO-8601 string")
    if isinstance(value, (int, float)):
        return int(value)
    if value is None:
        raise ValueError("timestamp is required")

    text = str(value).strip()
    if not text:
        raise ValueError("timestamp is required")
    try:
        return int(float(text))
    except ValueError:
        return parse_iso_timestamp(text)


def parse_iso_timestamp(value: str) -> int:
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError("timestamp must be an integer, numeric string, or ISO-8601 string") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    else:
        parsed = parsed.astimezone(UTC)
    return int(parsed.timestamp() * 1000)


def coerce_metadata(value: Any) -> dict[str, Any]:
    if value in (None, ""):
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("metadata must be a JSON object") from exc
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("metadata must be a JSON object")


def _merge_extra_metadata(metadata: dict[str, Any], raw: dict[str, Any], consumed_keys: set[str]) -> None:
    """
    Preserve non-canonical top-level fields by folding them into metadata.
    """
    for key, value in raw.items():
        if key in consumed_keys:
            continue
        if key not in metadata and value not in (None, ""):
            metadata[key] = value


def _first_value(d: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """Return the value for the first key in `keys` that exists in `d`."""
    for k in keys:
        if k in d:
            return d[k]
    return None


def validate_event(event: dict[str, Any]) -> None:
    """
    Validate that a normalized event satisfies the Event schema.
    """
    for key in REQUIRED_KEYS:
        if key not in event:
            raise ValueError(f"missing required key: {key}")

    if not isinstance(event["timestamp"], int):
        raise ValueError("timestamp must be int")

    for key in ("source_ip", "user", "action", "target"):
        if not isinstance(event[key], str):
            raise ValueError(f"{key} must be string")
        if not event[key].strip():
            raise ValueError(f"{key} cannot be empty")

    validate_ip_field(event["source_ip"], "source_ip")

    metadata = event["metadata"]
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be dict")
    destination_ip = metadata.get("destination_ip")
    if destination_ip not in (None, ""):
        metadata["destination_ip"] = validate_ip_field(str(destination_ip), "destination_ip")


def validate_ip_field(value: str, field_name: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IPv4 or IPv6 address: {value}") from exc


if __name__ == "__main__":
    sys.exit(main())
