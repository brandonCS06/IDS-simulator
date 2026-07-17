import argparse
import csv
import datetime
import ipaddress
import json
import logging
import random
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, TextIO, TypedDict


LOGGER = logging.getLogger(__name__)
UTC = datetime.timezone.utc


class Event(TypedDict):
    timestamp: int
    source_ip: str
    user: str
    action: str
    target: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class GenerationConfig:
    output: str = "Events.json"
    output_format: str = "json"
    normal: int = 10
    attacks: int = 1
    attempts_per_attack: int = 5
    portscans: int = 1
    ports_per_scan: int = 30
    dnsattacks: int = 1
    dns_queries_per_attack: int = 6
    icmpsweeps: int = 1
    icmp_targets_per_sweep: int = 30
    seed: int | None = None
    base_time: str | None = None


NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.2.20"]
ATTACK_IPS = ["10.0.0.5", "10.0.0.6", "203.0.113.1"]
USERS = ["alice", "bob", "charlie", "diana", "eve"]
ACTIONS = ["LOGIN_SUCCESS", "LOGIN_FAIL", "ACCESS_GRANTED", "ACCESS_DENIED"]
TARGETS = ["web_server", "database", "file_system", "api_gateway"]
CSV_FIELDS = ("timestamp", "source_ip", "user", "action", "target", "metadata")


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def require_ip_address(value: str, field_name: str = "ip") -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IPv4 or IPv6 address: {value}") from exc


def ip_scope(value: str) -> str:
    address = ipaddress.ip_address(value)
    if address.is_loopback:
        return "loopback"
    if address.is_multicast:
        return "multicast"
    if address.is_private:
        return "private"
    if address.is_reserved:
        return "reserved"
    return "public"


def ensure_utc(value: datetime.datetime | None = None) -> datetime.datetime:
    if value is None:
        return datetime.datetime.now(UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_datetime(value: str | None) -> datetime.datetime:
    if value is None:
        return datetime.datetime.now(UTC)
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        return ensure_utc(datetime.datetime.fromisoformat(cleaned))
    except ValueError as exc:
        raise ValueError(
            "base time must be ISO-8601, for example 2026-07-15T12:00:00Z"
        ) from exc


def epoch_ms(value: datetime.datetime) -> int:
    return int(ensure_utc(value).timestamp() * 1000)


def generate_icmp_destination_ip(index: int) -> str:
    """Generate a unique destination IP for ICMP sweep traffic."""
    return require_ip_address(f"198.51.100.{(index % 250) + 1}", "destination_ip")


def generate_timestamp(
    base_time: datetime.datetime | None = None,
    max_offset_seconds: int = 3600,
    rng: random.Random | None = None,
) -> int:
    """
    Generate a timestamp in epoch milliseconds.
    - base_time: Starting datetime (default: current UTC time).
    - max_offset_seconds: Max random offset to spread events.
    - rng: Optional random generator for reproducible simulations.
    """
    generator = rng or random
    base = ensure_utc(base_time)
    offset = generator.randint(0, max_offset_seconds)
    event_time = base + datetime.timedelta(seconds=offset)
    return epoch_ms(event_time)


def generate_ip(is_attack: bool = False, rng: random.Random | None = None) -> str:
    """
    Generate a random IP address.
    - is_attack: If True, pick from attack IPs; else, normal IPs.
    """
    generator = rng or random
    pool = ATTACK_IPS if is_attack else NORMAL_IPS
    return require_ip_address(generator.choice(pool), "source_ip")


def generate_user(rng: random.Random | None = None) -> str:
    """Generate a random username."""
    generator = rng or random
    return generator.choice(USERS)


def generate_event(
    action: str,
    source_ip: str,
    user: str | None = None,
    target: str | None = None,
    timestamp: int | None = None,
    metadata: dict[str, Any] | None = None,
    rng: random.Random | None = None,
) -> Event:
    """
    Generate a single event dict in Event schema.
    - action: e.g., "LOGIN_SUCCESS"
    - source_ip: IP address
    - user: Username (random if not provided)
    - target: Target service (random if not provided)
    - timestamp: Epoch ms (current UTC if not provided)
    - metadata: Extra dict (empty if not provided)
    """
    generator = rng or random
    normalized_source_ip = require_ip_address(source_ip, "source_ip")
    if user is None:
        user = generate_user(generator)
    if target is None:
        target = generator.choice(TARGETS)
    if timestamp is None:
        timestamp = generate_timestamp(rng=generator)

    event_metadata = dict(metadata or {})
    event_metadata.setdefault("source_ip_scope", ip_scope(normalized_source_ip))
    destination_ip = event_metadata.get("destination_ip")
    if destination_ip is not None:
        event_metadata["destination_ip"] = require_ip_address(str(destination_ip), "destination_ip")
        event_metadata.setdefault("destination_ip_scope", ip_scope(event_metadata["destination_ip"]))

    return {
        "timestamp": int(timestamp),
        "source_ip": normalized_source_ip,
        "user": str(user),
        "action": str(action),
        "target": str(target),
        "metadata": event_metadata,
    }


def generate_normal_activity(
    num_events: int = 10,
    base_time: datetime.datetime | None = None,
    rng: random.Random | None = None,
) -> list[Event]:
    """Generate a list of normal activity events."""
    generator = rng or random
    events: list[Event] = []
    for _ in range(num_events):
        ip = generate_ip(is_attack=False, rng=generator)
        action = generator.choice(["LOGIN_SUCCESS", "ACCESS_GRANTED"])
        event = generate_event(action, ip, timestamp=generate_timestamp(base_time, rng=generator), rng=generator)
        events.append(event)
    return events


def generate_attack_activity(
    num_attempts: int = 5,
    base_time: datetime.datetime | None = None,
    rng: random.Random | None = None,
) -> list[Event]:
    """Generate a list of attack activity events, such as rapid failed logins."""
    generator = rng or random
    events: list[Event] = []
    ip = generate_ip(is_attack=True, rng=generator)
    user = generate_user(generator)
    for i in range(num_attempts):
        max_offset = 10 if i == 0 else 1
        timestamp = generate_timestamp(base_time, max_offset_seconds=max_offset, rng=generator)
        event = generate_event("LOGIN_FAIL", ip, user=user, timestamp=timestamp, metadata={"attempt": i + 1}, rng=generator)
        events.append(event)
    return events


def generate_port_scan_activity(
    num_ports: int = 30,
    base_time: datetime.datetime | None = None,
    rng: random.Random | None = None,
) -> list[Event]:
    """Generate a list of port scan activity events."""
    generator = rng or random
    events: list[Event] = []
    ip = generate_ip(is_attack=True, rng=generator)
    user = generate_user(generator)
    base = ensure_utc(base_time)

    ports = list(range(1024, 1024 + num_ports))
    for i, port in enumerate(ports):
        timestamp = epoch_ms(base + datetime.timedelta(milliseconds=i * 200))
        metadata = {"destination_port": port, "attempt": i + 1}
        event = generate_event("PROBE", ip, user=user, timestamp=timestamp, metadata=metadata, rng=generator)
        events.append(event)
    return events


def generate_suspicious_dns_activity(
    num_queries: int = 6,
    base_time: datetime.datetime | None = None,
    rng: random.Random | None = None,
) -> list[Event]:
    """Generate a list of suspicious DNS activity events."""
    generator = rng or random
    events: list[Event] = []
    ip = generate_ip(is_attack=True, rng=generator)
    user = generate_user(generator)
    base = ensure_utc(base_time)

    for i in range(num_queries):
        timestamp = epoch_ms(base + datetime.timedelta(milliseconds=i * 250))
        token = "".join(generator.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(18 + i))
        query_name = f"{token}.exfil.example.com"
        metadata = {
            "protocol": "DNS",
            "query_name": query_name,
            "qtype": generator.choice(["TXT", "NULL", "AAAA"]),
            "rcode": generator.choice(["NXDOMAIN", "SERVFAIL", "NOERROR"]),
            "response_size": generator.randint(48, 820),
            "label_length": len(token),
            "entropy": round(generator.uniform(4.0, 5.5), 2),
            "attempt": i + 1,
        }
        event = generate_event("DNS_QUERY", ip, user=user, target="dns_resolver", timestamp=timestamp, metadata=metadata, rng=generator)
        events.append(event)
    return events


def generate_icmp_sweep_activity(
    num_targets: int = 30,
    base_time: datetime.datetime | None = None,
    rng: random.Random | None = None,
) -> list[Event]:
    """Generate a list of ICMP sweep activity events."""
    generator = rng or random
    events: list[Event] = []
    ip = generate_ip(is_attack=True, rng=generator)
    user = generate_user(generator)
    base = ensure_utc(base_time)

    for i in range(num_targets):
        timestamp = epoch_ms(base + datetime.timedelta(milliseconds=i * 200))
        destination_ip = generate_icmp_destination_ip(i)
        metadata = {
            "protocol": "ICMP",
            "icmp_type": 8,
            "destination_ip": destination_ip,
            "attempt": i + 1,
        }
        event = generate_event("ICMP_ECHO_REQUEST", ip, user=user, target="icmp_probe", timestamp=timestamp, metadata=metadata, rng=generator)
        events.append(event)
    return events


def load_config(path: str | None) -> dict[str, Any]:
    if path is None:
        return {}
    config_path = Path(path)
    with config_path.open("rb") as f:
        if config_path.suffix.lower() == ".json":
            return json.load(f)
        return tomllib.load(f)


def build_config(args: argparse.Namespace) -> GenerationConfig:
    data = asdict(GenerationConfig())
    data.update(load_config(args.config))
    for key, value in vars(args).items():
        if key in {"config", "verbose"}:
            continue
        if value is not None:
            data[key] = value
    return GenerationConfig(**data)


def generate_events(config: GenerationConfig) -> list[Event]:
    rng = random.Random(config.seed) if config.seed is not None else random
    base_time = parse_datetime(config.base_time)

    events: list[Event] = []
    events.extend(generate_normal_activity(config.normal, base_time, rng))
    for _ in range(config.attacks):
        events.extend(generate_attack_activity(config.attempts_per_attack, base_time, rng))
    for _ in range(config.portscans):
        events.extend(generate_port_scan_activity(config.ports_per_scan, base_time, rng))
    for _ in range(config.dnsattacks):
        events.extend(generate_suspicious_dns_activity(config.dns_queries_per_attack, base_time, rng))
    for _ in range(config.icmpsweeps):
        events.extend(generate_icmp_sweep_activity(config.icmp_targets_per_sweep, base_time, rng))

    events.sort(key=lambda e: e["timestamp"])
    return events


def flatten_event_for_csv(event: Event) -> dict[str, Any]:
    row: dict[str, Any] = dict(event)
    row["metadata"] = json.dumps(event["metadata"], sort_keys=True)
    return row


def write_events(events: list[Event], path: str, output_format: str = "json") -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        write_events_to_stream(events, f, output_format)


def write_events_to_stream(events: list[Event], stream: TextIO, output_format: str = "json") -> None:
    if output_format == "json":
        json.dump(events, stream, indent=4)
        stream.write("\n")
        return
    if output_format == "jsonl":
        for event in events:
            stream.write(json.dumps(event, sort_keys=True))
            stream.write("\n")
        return
    if output_format == "csv":
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(flatten_event_for_csv(event) for event in events)
        return
    raise ValueError(f"unsupported output format: {output_format}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate simulated network activity logs.")
    parser.add_argument("--config", help="Optional TOML or JSON config file.")
    parser.add_argument("--output", help="Output path (default: Events.json).")
    parser.add_argument("--output_format", choices=["json", "jsonl", "csv"], help="Output format.")
    parser.add_argument("--normal", "--count", dest="normal", type=int, help="Number of normal events to generate.")
    parser.add_argument("--attacks", type=int, help="Number of attack sequences to generate.")
    parser.add_argument("--attempts_per_attack", type=int, help="Failed attempts per attack.")
    parser.add_argument("--portscans", type=int, help="Number of port scan sequences to generate.")
    parser.add_argument("--ports_per_scan", type=int, help="Unique destination ports per port scan sequence.")
    parser.add_argument("--dnsattacks", type=int, help="Number of suspicious DNS sequences to generate.")
    parser.add_argument("--dns_queries_per_attack", type=int, help="DNS queries per suspicious DNS sequence.")
    parser.add_argument("--icmpsweeps", type=int, help="Number of ICMP sweep sequences to generate.")
    parser.add_argument("--icmp_targets_per_sweep", type=int, help="Unique destination IPs per ICMP sweep sequence.")
    parser.add_argument("--seed", type=int, help="Seed for reproducible simulations.")
    parser.add_argument("--base_time", help="UTC ISO-8601 base time, such as 2026-07-15T12:00:00Z.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)
    try:
        config = build_config(args)
        events = generate_events(config)
        write_events(events, config.output, config.output_format)
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError, TypeError) as exc:
        LOGGER.error("%s", exc)
        return 1

    LOGGER.info("Generated %d events and saved to %s", len(events), config.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
