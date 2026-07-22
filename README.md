# Network IDS Simulator

A Network Intrusion Detection System (IDS) simulator that processes network-style security events and detects suspicious activity using configurable detection rules. The project combines a Java event-processing engine with Python tools for generating logs, parsing inputs, and building reports.

## Quick Start

### Prerequisites

- **Java**: JDK 8 or later
- **Maven**: 3.6+
- **Python**: 3.11+

### Run the Demo

Run the full demo pipeline:

```bash
python python/demo.py
```

This will:

1. Generate synthetic network events
2. Compile the Java IDS engine
3. Run the IDS against the generated events
4. Generate an HTML report

Demo output is written to `demo-output/`:

```text
demo-output/Events.json
demo-output/Alerts.json
demo-output/report.html
```

Open `demo-output/report.html` in a browser to review the alert dashboard. Existing demo artifacts are replaced each time the demo runs.

### Run Tests

```bash
mvn test
```

## Common Commands

### Build the Java Project

```bash
mvn clean compile
mvn package
```

### Run a Specific Demo Scenario

```bash
python python/demo.py --scenario syn-flood
python python/demo.py --scenario port-scan
python python/demo.py --scenario dns-tunnel
```

### Run a Reproducible Demo

```bash
python python/demo.py --seed 42 --base-time 2026-07-15T12:00:00Z
```

### Run With Custom Rule Thresholds

```bash
python python/demo.py --rules rules.example.json
```

### Run the Java IDS Manually

Linux/macOS:

```bash
java -cp "target/classes:$HOME/.m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar" com.ids.IDSCore Events.json
```

Windows PowerShell:

```powershell
java -cp "target/classes;$env:USERPROFILE\.m2\repository\com\google\code\gson\gson\2.10.1\gson-2.10.1.jar" com.ids.IDSCore Events.json
```

Pass a custom event file as the first argument:

```bash
java -cp "target/classes:$HOME/.m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar" com.ids.IDSCore path/to/events.json
```

Pass a rule config file as the second argument:

```bash
java -cp "target/classes:$HOME/.m2/repository/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar" com.ids.IDSCore Events.json rules.example.json
```

## Python Utilities

| Task | Command |
|---|---|
| Generate synthetic events | `python python/log_generator.py --output Events.json --normal 1000 --seed 42` |
| Generate DNS attack traffic | `python python/log_generator.py --output Events.json --dnsattacks 1 --dns_queries_per_attack 6` |
| Generate ICMP sweep traffic | `python python/log_generator.py --output Events.json --icmpsweeps 1 --icmp_targets_per_sweep 30` |
| Generate SYN flood traffic | `python python/log_generator.py --output Events.json --synfloods 1 --syn_packets_per_flood 80 --acks_per_flood 5` |
| Export generated events as JSONL | `python python/log_generator.py --output sample-events.jsonl --output_format jsonl --seed 42` |
| Export generated events as CSV | `python python/log_generator.py --output sample-events.csv --output_format csv --seed 42` |
| Parse JSONL logs | `python python/log_parser.py --input sample-events.jsonl --format jsonl --output Events.json` |
| Parse CSV logs | `python python/log_parser.py --input sample-events.csv --format csv --output Events.json` |
| Generate console report | `python python/report_generator.py` |
| Generate JSON report | `python python/report_generator.py --format json --output report.json` |
| Generate CSV report | `python python/report_generator.py --format csv --output report.csv` |
| Generate HTML report | `python python/report_generator.py --format html --output report.html` |

The parser accepts `json`, `events-json`, `jsonl`, and `csv` input. It validates IP addresses, accepts epoch-millisecond or ISO-8601 timestamps, and writes a Java-compatible `Events.json` array.

## Detection Rules

| Rule | Detects | Default threshold |
|---|---|---|
| `BruteForceRule` | Repeated failed login attempts from one source IP | 5+ failed logins in 60 seconds |
| `PortScanRule` | One source IP connecting to many destination ports | 30+ ports in 60 seconds |
| `IcmpSweepRule` | One host pinging many destination IPs | 30+ destination IPs in 60 seconds |
| `SuspiciousDnsRule` | DNS tunneling or exfiltration indicators | Score-based DNS indicators in 60 seconds |
| `SynFloodRule` | Bursty TCP SYN traffic with low ACK completion | 60+ SYN packets in 10 seconds with ACK ratio below 0.20 |

Generated alerts include supporting evidence, plain-English descriptions, recommendations, and rule-specific metrics.

## Configuration

### Python Simulation Settings

The event generator accepts TOML or JSON config files for repeatable lab runs:

```toml
output = "Events.json"
output_format = "json"
normal = 500
attacks = 2
attempts_per_attack = 5
portscans = 1
ports_per_scan = 30
dnsattacks = 1
dns_queries_per_attack = 6
icmpsweeps = 1
icmp_targets_per_sweep = 30
synfloods = 1
syn_packets_per_flood = 80
acks_per_flood = 5
seed = 42
base_time = "2026-07-15T12:00:00Z"
```

Run it with:

```bash
python python/log_generator.py --config simulation.toml
```

### Java Rule Settings

The Java IDS engine accepts an optional JSON rule config file. Start from `rules.example.json`:

```json
{
  "brute_force": {
    "window_ms": 60000,
    "threshold": 5
  },
  "port_scan": {
    "window_ms": 60000,
    "port_threshold": 30
  },
  "suspicious_dns": {
    "window_ms": 60000,
    "minimum_dns_events": 5,
    "score_threshold": 8
  },
  "syn_flood": {
    "window_ms": 10000,
    "syn_threshold": 60,
    "minimum_syn_for_ratio": 30,
    "max_ack_ratio": 0.2
  },
  "icmp_sweep": {
    "window_ms": 60000,
    "icmp_threshold": 30
  },
  "[custom rule name]": {
    "thresholds": "threshold values",
    "..."
  }
}
```

Any omitted section uses the built-in default values.

## Adding Custom Rules

Implement the `RuleEngineRules` interface:

```java
public class CustomRule implements RuleEngineRules {
    @Override
    public List<Alert> onEvent(Event event) {
        // Your detection logic here
        if (threatDetected) {
            return List.of(new Alert(...));
        }
        return new ArrayList<>();
    }
}
```

Then register it in `IDSCore`:

```java
ruleEngine.registerRule(new CustomRule());
```

For threshold configurations, register the rule in `rules.example.json`.

## Input and Output

### Event Schema

Events follow this JSON structure:

```json
{
  "timestamp": 1234567890000,
  "source_ip": "192.168.1.10",
  "user": "alice",
  "action": "LOGIN_SUCCESS",
  "target": "web_server",
  "metadata": {
    "session_id": "abc123",
    "duration_ms": 5000,
    "protocol": "DNS",
    "query_name": "token.exfil.example.com",
    "qtype": "TXT",
    "rcode": "NXDOMAIN",
    "response_size": 600,
    "label_length": 24,
    "entropy": 4.8
  }
}
```

ICMP sweep events should include `icmp_type: 8` and `destination_ip` in `metadata`.

### Alert Schema

Generated alerts include:

```json
{
  "timestamp": 1234567890000,
  "rule_name": "BruteForceRule",
  "severity": "high",
  "source_ip": "10.0.0.5",
  "description": "Source 10.0.0.5 produced 5 failed login attempts within 60 seconds, meeting the brute-force threshold of 5.",
  "recommendation": "Review authentication logs for the source IP, verify whether the user activity is legitimate, and consider rate limiting or temporary blocking.",
  "metrics": {
    "failed_login_count": 5,
    "threshold": 5,
    "window_ms": 60000,
    "window_seconds": 60
  },
  "evidence": []
}
```

The exact `metrics` fields depend on the rule. For example, `SynFloodRule` includes `syn_count`, `ack_count`, `ack_ratio`, `destination_ip`, and `destination_port`, while `SuspiciousDnsRule` includes `score` and `indicators`.

### Output Files

- **Alerts.json** - Complete alert data with evidence
- **Events.json** - Normalized input events for the Java IDS engine
- Optional **report.json**, **report.csv**, or **report.html** from the Python reporter
- Console output with processing statistics

## Architecture

### Core Components

#### Java Engine (`src/main/java/com/ids/`)

- **IDSCore** - Main orchestrator that loads events, processes them through the rule engine, and exports alerts
- **RuleEngine** - Evaluates each security event against registered detection rules
- **RuleEngineRules** - Interface for implementing custom threat detection rules
- **BruteForceRule** - Detects brute force login attacks using a sliding time window with configurable thresholds
- **PortScanRule** - Detects port scan behavior
- **IcmpSweepRule** - Detects ICMP sweep behavior
- **SuspiciousDnsRule** - Detects suspicious DNS tunneling patterns
- **SynFloodRule** - Detects SYN flood patterns
- **SlidingWindow** - Time-based event window for tracking recent events
- **Event** - Canonical representation of a security event
- **Alert** - Generated when a rule detects suspicious activity
- **AlertManager** - Manages alert collection and exports to JSON

#### Python Utilities (`python/`)

- **demo.py** - Runs the end-to-end demo pipeline
- **log_generator.py** - Generates synthetic security events
- **log_parser.py** - Parses raw logs into the standardized Event format
- **report_generator.py** - Summarizes alerts and exports reports

### Data Flow

```text
Events.json (input)
    |
    v
IDSCore.loadEvents()
    |
    v
RuleEngine.processEvent()
    |
    v
Rule.onEvent()
    |
    v
AlertManager
    |
    v
Alerts.json (output) + Report
```

## Project Structure

```text
IDS-simulator/
|-- pom.xml
|-- Alerts.json
|-- Events.json
|-- README.md
|-- src/
|   `-- main/java/com/ids/
|       |-- IDSCore.java
|       |-- RuleEngine.java
|       |-- RuleEngineRules.java
|       |-- BruteForceRule.java
|       |-- PortScanRule.java
|       |-- IcmpSweepRule.java
|       |-- SynFloodRule.java
|       |-- Event.java
|       |-- Alert.java
|       |-- AlertManager.java
|       |-- SlidingWindow.java
|       `-- SuspiciousDnsRule.java
`-- python/
    |-- demo.py
    |-- log_generator.py
    |-- log_parser.py
    `-- report_generator.py
```

## Dependencies

- **GSON 2.10.1** - JSON serialization/deserialization
- **Java Compiler Source/Target**: Java 8

## Future Potential Enhancements

- Integration with a VM homelab
- Additional detection rules such as DDoS, privilege escalation, and anomalous behavior
- Performance optimization for large event volumes
- Machine learning-based anomaly detection
- SIEM platform integration

## License

Read License.md

## Author

Developed by Brandon Le, Computer Science Student at Rutgers University - New Brunswick.
