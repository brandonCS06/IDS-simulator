import json
import random
import datetime
import argparse

# Constants for simulation
NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.2.20"]
ATTACK_IPS = ["10.0.0.5", "10.0.0.6", "203.0.113.1"]
USERS = ["alice", "bob", "charlie", "diana", "eve"]
ACTIONS = ["LOGIN_SUCCESS", "LOGIN_FAIL", "ACCESS_GRANTED", "ACCESS_DENIED"]
TARGETS = ["web_server", "database", "file_system", "api_gateway"]

def generate_timestamp(base_time=None, max_offset_seconds=3600):
    """
    Generate a timestamp in epoch milliseconds.
    - base_time: Starting datetime (default: current time).
    - max_offset_seconds: Max random offset to spread events.
    """
    if base_time is None:
        base_time = datetime.datetime.now()
    offset = random.randint(0, max_offset_seconds)
    event_time = base_time + datetime.timedelta(seconds=offset)
    return int(event_time.timestamp() * 1000)  # Convert to milliseconds

def generate_ip(is_attack=False):
    """
    Generate a random IP address.
    - is_attack: If True, pick from attack IPs; else, normal IPs.
    """
    pool = ATTACK_IPS if is_attack else NORMAL_IPS
    return random.choice(pool)

def generate_user():
    """Generate a random username."""
    return random.choice(USERS)

def generate_event(action, source_ip, user=None, target=None, timestamp=None, metadata=None):
    """
    Generate a single event dict in Event schema.
    - action: e.g., "LOGIN_SUCCESS"
    - source_ip: IP address
    - user: Username (random if not provided)
    - target: Target service (random if not provided)
    - timestamp: Epoch ms (current if not provided)
    - metadata: Extra dict (empty if not provided)
    """
    if user is None:
        user = generate_user()
    if target is None:
        target = random.choice(TARGETS)
    if timestamp is None:
        timestamp = generate_timestamp()
    if metadata is None:
        metadata = {}
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "user": user,
        "action": action,
        "target": target,
        "metadata": metadata
    }

def generate_normal_activity(num_events=10, base_time=None):
    """
    Generate a list of normal activity events.
    - num_events: Number of events to generate.
    - base_time: Base timestamp for events.
    """
    events = []
    for _ in range(num_events):
        ip = generate_ip(is_attack=False)
        action = random.choice(["LOGIN_SUCCESS", "ACCESS_GRANTED"])  # Mostly positive
        event = generate_event(action, ip, timestamp=generate_timestamp(base_time))
        events.append(event)
    return events

def generate_attack_activity(num_attempts=5, base_time=None):
    """
    Generate a list of attack activity events (e.g., brute-force login attempts).
    - num_attempts: Number of failed attempts.
    - base_time: Base timestamp; subsequent events are close in time.
    """
    events = []
    ip = generate_ip(is_attack=True)
    user = generate_user()  # Same user for the attack
    for i in range(num_attempts):
        # Small offset for rapid attempts
        timestamp = generate_timestamp(base_time, max_offset_seconds=10) if i == 0 else generate_timestamp(base_time, max_offset_seconds=1)
        event = generate_event("LOGIN_FAIL", ip, user=user, timestamp=timestamp, metadata={"attempt": i+1})
        events.append(event)
    return events


def generate_port_scan_activity(num_ports=30, base_time=None):
    """
    Generate a list of port scan activity events.
    - num_ports: Number of unique destination ports to probe.
    - base_time: Base timestamp for the scan.
    """
    events = []
    ip = generate_ip(is_attack=True)
    user = generate_user()
    if base_time is None:
        base_time = datetime.datetime.now()

    ports = list(range(1024, 1024 + num_ports))
    for i, port in enumerate(ports):
        timestamp = int((base_time + datetime.timedelta(milliseconds=i * 200)).timestamp() * 1000)
        metadata = {"destination_port": port, "attempt": i + 1}
        event = generate_event("PROBE", ip, user=user, timestamp=timestamp, metadata=metadata)
        events.append(event)
    return events


def generate_suspicious_dns_activity(num_queries=6, base_time=None):
    """
    Generate a list of suspicious DNS activity events.
    - num_queries: Number of DNS queries to generate for one source IP.
    - base_time: Base timestamp for the query burst.
    """
    events = []
    ip = generate_ip(is_attack=True)
    user = generate_user()
    if base_time is None:
        base_time = datetime.datetime.now()

    for i in range(num_queries):
        timestamp = int((base_time + datetime.timedelta(milliseconds=i * 250)).timestamp() * 1000)
        token = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(18 + i))
        query_name = f"{token}.exfil.example.com"
        metadata = {
            "protocol": "DNS",
            "query_name": query_name,
            "qtype": random.choice(["TXT", "NULL", "AAAA"]),
            "rcode": random.choice(["NXDOMAIN", "SERVFAIL", "NOERROR"]),
            "response_size": random.randint(48, 820),
            "label_length": len(token),
            "entropy": round(random.uniform(4.0, 5.5), 2),
            "attempt": i + 1,
        }
        event = generate_event("DNS_QUERY", ip, user=user, target="dns_resolver", timestamp=timestamp, metadata=metadata)
        events.append(event)
    return events


def main():
    parser = argparse.ArgumentParser(description="Generate simulated network activity logs in JSON format.")
    parser.add_argument("--output", default="Events.json", help="Output JSON file path (default: Events.json).")
    parser.add_argument("--normal", type=int, default=10, help="Number of normal events to generate.")
    parser.add_argument("--attacks", type=int, default=1, help="Number of attack sequences to generate.")
    parser.add_argument("--attempts_per_attack", type=int, default=5, help="Failed attempts per attack.")
    parser.add_argument("--portscans", type=int, default=1, help="Number of port scan sequences to generate.")
    parser.add_argument("--ports_per_scan", type=int, default=30, help="Unique destination ports per port scan sequence.")
    parser.add_argument("--dnsattacks", type=int, default=1, help="Number of suspicious DNS sequences to generate.")
    parser.add_argument("--dns_queries_per_attack", type=int, default=6, help="DNS queries per suspicious DNS sequence.")
    args = parser.parse_args()

    base_time = datetime.datetime.now()

    # Generate events
    events = []
    events.extend(generate_normal_activity(args.normal, base_time))
    for _ in range(args.attacks):
        events.extend(generate_attack_activity(args.attempts_per_attack, base_time))
    for _ in range(args.portscans):
        events.extend(generate_port_scan_activity(args.ports_per_scan, base_time))
    for _ in range(args.dnsattacks):
        events.extend(generate_suspicious_dns_activity(args.dns_queries_per_attack, base_time))

    # Sort by timestamp for realism
    events.sort(key=lambda e: e["timestamp"])

    # Write to JSON file
    with open(args.output, "w") as f:
        json.dump(events, f, indent=4)
    print(f"Generated {len(events)} events and saved to {args.output}")

if __name__ == "__main__":
    main()