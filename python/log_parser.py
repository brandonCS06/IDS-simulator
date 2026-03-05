import argparse
import json
import os
import sys
from pathlib import Path

"""
Utility CLI for converting raw log files into a normalized `Events.json`
payload that the Java IDS core can consume. It accepts both already-normalized
`events-json` input and more generic JSON logs, coercing them into a
consistent Event schema and validating required fields before writing.
"""

# Default output path: Events.json in project root 
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "Events.json"

REQUIRED_KEYS = ("timestamp", "source_ip", "user", "action", "target", "metadata")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse raw log files into Events.json for Java IDS core."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to raw log file (JSON).",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"Output path for Events.json (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "events-json"],
        default="json",
        help="Input format: 'events-json' (already in schema) or 'json' (generic, needs normalization).",
    )
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()

    try:
        raw_records = load_raw_records(str(input_path), args.format)
    except FileNotFoundError:
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {input_path}: {e}", file=sys.stderr)
        sys.exit(1)

    events = []
    for i, raw in enumerate(raw_records):
        if not isinstance(raw, dict):
            print(f"Error: Record at index {i} is not a JSON object.", file=sys.stderr)
            sys.exit(1)
        try:
            event = normalize_record(raw, args.format)
            validate_event(event)
            events.append(event)
        except ValueError as e:
            print(f"Error: Record at index {i}: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        write_events(events, str(output_path))
    except OSError as e:
        print(f"Error: Failed to write output: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Wrote {len(events)} event(s) to {output_path}", file=sys.stderr)


def load_raw_records(path: str, fmt: str) -> list:
    """
    Load raw records from disk based on the declared input format.

    For `events-json`, this expects a top-level JSON array of already
    normalized event-like objects. For generic `json`, this accepts either
    a single object or an array and returns a list of dicts in both cases.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if fmt == "events-json":
        if not isinstance(data, list):
            raise ValueError("events-json format expects a top-level JSON array")
        return data

    # Generic json: accept list or single object
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    raise ValueError("Input JSON must be an array or object")


def write_events(events: list, path: str) -> None:
    """
    Persist the normalized events to disk as pretty-printed JSON.

    This will create parent directories as needed so the Java side can
    reliably load `Events.json` without worrying about filesystem layout.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=4)


def normalize_record(raw: dict, fmt: str) -> dict:
    """
    Map a single raw input record into the canonical Event schema
    (`timestamp`, `source_ip`, `user`, `action`, `target`, `metadata`).

    The `fmt` flag determines whether we treat the record as already
    mostly conformant (`events-json`) or perform alias-based key lookup
    for generic JSON logs.
    """
    if fmt == "events-json":
        # Already has correct keys; normalize types and ensure metadata
        return _normalize_event_like(raw)

    # Generic json: remap common keys
    return _normalize_generic(raw)


def _normalize_event_like(raw: dict) -> dict:
    """
    Normalize a record that already exposes Event-like keys.

    This path mainly enforces types, trims strings and guarantees that
    `metadata` is present as an object, raising `ValueError` on schema
    violations so bad input fails fast.
    """
    out = {}
    # Timestamp
    t = raw.get("timestamp")
    if t is None:
        raise ValueError("missing required field: timestamp")
    try:
        out["timestamp"] = int(t)
    except (TypeError, ValueError):
        raise ValueError("timestamp must be an integer or numeric string")

    for key in ("source_ip", "user", "action", "target"):
        val = raw.get(key)
        if val is None:
            raise ValueError(f"missing required field: {key}")
        out[key] = str(val).strip()

    meta = raw.get("metadata")
    if meta is None:
        out["metadata"] = {}
    elif isinstance(meta, dict):
        out["metadata"] = meta
    else:
        raise ValueError("metadata must be a JSON object")
    return out


# Common alternate keys for generic JSON
KEY_ALIASES = {
    "timestamp": ("timestamp", "time", "ts", "unix", "date"),
    "source_ip": ("source_ip", "ip", "source_ip_address", "client_ip"),
    "user": ("user", "username", "uid"),
    "action": ("action", "event", "event_type", "type"),
    "target": ("target", "service", "resource", "target_service"),
    "metadata": ("metadata", "meta", "extra", "details"),
}


def _normalize_generic(raw: dict) -> dict:
    """
    Normalize a generic JSON record by looking up multiple possible key
    aliases (e.g. `ip` vs `source_ip`) and coercing values into the
    expected Event types.

    This is the flexible path intended for loosely structured log
    sources; missing or incompatible fields are surfaced as `ValueError`.
    """
    out = {}

    # Timestamp
    t = _first_value(raw, KEY_ALIASES["timestamp"])
    if t is None:
        raise ValueError("missing required field: timestamp (or time/ts)")
    try:
        out["timestamp"] = int(t)
    except (TypeError, ValueError):
        raise ValueError("timestamp must be an integer or numeric string")

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

    meta = _first_value(raw, KEY_ALIASES["metadata"])
    if meta is None:
        out["metadata"] = {}
    elif isinstance(meta, dict):
        out["metadata"] = meta
    else:
        raise ValueError("metadata must be a JSON object")
    return out


def _first_value(d: dict, keys: tuple):
    """
    Return the value for the first key in `keys` that exists in `d`.

    This helper drives alias resolution for generic logs so that a
    variety of upstream field names can be mapped into one schema.
    """
    for k in keys:
        if k in d:
            return d[k]
    return None


def validate_event(event: dict) -> None:
    """
    Validate that a normalized event satisfies the Event schema.

    Ensures all required keys exist and have the expected types; any
    violation is raised as `ValueError` so the caller can surface a
    clear error and halt processing rather than emitting bad data.
    """
    for key in REQUIRED_KEYS:
        if key not in event:
            raise ValueError(f"missing required key: {key}")

    if not isinstance(event["timestamp"], int):
        raise ValueError("timestamp must be int")

    for key in ("source_ip", "user", "action", "target"):
        if not isinstance(event[key], str):
            raise ValueError(f"{key} must be string")

    if not isinstance(event["metadata"], dict):
        raise ValueError("metadata must be dict")


if __name__ == "__main__":
    main()
