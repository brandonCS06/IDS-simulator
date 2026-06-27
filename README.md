# IDS Simulator

An Intrusion Detection System (IDS) simulator that processes security events and detects suspicious activities using configurable detection rules. The system combines a Java-based event processing engine with Python utilities for log generation, parsing, and reporting.

## Overview

The IDS Simulator is designed to:
- **Simulate realistic network activity** with normal and attack patterns
- **Process security events** in real-time against detection rules
- **Detect threats** using rule-based analysis (e.g., brute force attacks)
- **Generate alerts** with evidence-based findings
- **Report findings** with summary statistics and threat analysis

## Architecture

### Core Components

#### Java Engine (`src/main/java/com/ids/`)

- **IDSCore** - Main orchestrator that loads events, processes them through the rule engine, and exports alerts
- **RuleEngine** - Evaluates each security event against registered detection rules
- **RuleEngineRules** - Interface for implementing custom threat detection rules
- **BruteForceRule** - Detects brute force login attacks using a sliding time window with configurable thresholds
- **SlidingWindow** - Time-based event window (1-minute default) for tracking events by source IP and action type
- **Event** - Canonical representation of a security event (timestamp, source IP, user, action, target, metadata)
- **Alert** - Generated when a rule detects suspicious activity; includes severity, rule name, and supporting evidence
- **AlertManager** - Manages alert collection and exports to JSON format

#### Python Utilities (`python/`)

- **log_generator.py** - Generates synthetic security events with configurable normal and attack traffic patterns
- **log_parser.py** - Parses raw logs into the standardized Event format
- **report_generator.py** - Summarizes alerts with statistics by rule, source IP, and top attackers

### Data Flow

```
Events.json (input)
    ↓
IDSCore.loadEvents()
    ↓
RuleEngine.processEvent() [runs each event through all rules]
    ↓
BruteForceRule.onEvent() [evaluates against detection logic]
    ↓
AlertManager [accumulates alerts]
    ↓
Alerts.json (output) + Report
```

## Getting Started

### Prerequisites

- **Java**: JDK 8 or later
- **Maven**: 3.6+ for building
- **Python**: 3.x for log generation and reporting utilities

### Building

```bash
mvn clean compile
mvn package
```

### Running the IDS

#### Basic Usage

```bash
java -cp target/classes com.ids.IDSCore Events.json
```

This will:
1. Load events from `Events.json`
2. Process them through registered detection rules
3. Export detected alerts to `Alerts.json`

#### With Custom Event File

```bash
java -cp target/classes com.ids.IDSCore path/to/events.json
```

### Python Utilities

#### Generate Synthetic Events

```bash
python python/log_generator.py --output Events.json --count 1000
```

Generates events with a mix of normal activity and attack patterns.

#### Generate Report

```bash
python python/report_generator.py
```

Outputs a summary of alerts including:
- Total alert count
- Alerts by detection rule
- Top attacking source IPs

## Detection Rules

### Current Rules

#### BruteForceRule
- **Purpose**: Detects repeated failed login attempts from the same source IP
- **Window**: 1-minute sliding window
- **Threshold**: 5+ failed login events
- **Severity**: High
- **Evidence**: List of failed login events that triggered the alert

### Adding Custom Rules

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

Then register in `IDSCore`:

```java
ruleEngine.registerRule(new CustomRule());
```

## Event Schema

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
    "duration_ms": 5000
  }
}
```

## Alert Schema

Generated alerts include:

```json
{
  "timestamp": 1234567890000,
  "rule_name": "BruteForceRule",
  "severity": "high",
  "source_ip": "10.0.0.5",
  "evidence": [...]
}
```

## Project Structure

```
IDS-simulator/
├── pom.xml                    # Maven project configuration
├── Alerts.json               # Generated alerts output
├── Events.json               # Input events
├── README.md                 # This file
├── src/
│   └── main/java/com/ids/
│       ├── IDSCore.java          # Main orchestrator
│       ├── RuleEngine.java        # Rule evaluation engine
│       ├── RuleEngineRules.java   # Rule interface
│       ├── BruteForceRule.java    # Brute force detection
│       ├── Event.java             # Event model
│       ├── Alert.java             # Alert model
│       ├── AlertManager.java      # Alert collection
│       └── SlidingWindow.java     # Time-based event window
└── python/
    ├── log_generator.py       # Synthetic event generation
    ├── log_parser.py          # Raw log parsing
    └── report_generator.py    # Alert report generation
```

## Dependencies

- **GSON 2.10.1** - JSON serialization/deserialization
- **Java Compiler Source/Target**: Java 8

## Usage Examples

### Example 1: Generate Events and Run IDS

```bash
# Generate synthetic events
python python/log_generator.py --output Events.json --count 500

# Compile the Java project
mvn clean compile

# Run the IDS
java -cp target/classes com.ids.IDSCore Events.json

# Generate a report
python python/report_generator.py
```

### Example 2: Process Custom Events

Place your `Events.json` file in the project root and run:

```bash
java -cp target/classes com.ids.IDSCore Events.json
```

## Configuration

### Brute Force Rule Settings

In `BruteForceRule.java`, adjust:

```java
private static final long time_Window_ms = 60_000;  // Time window in milliseconds
private static final int threshold = 5;             // Failed login threshold
```

## Output Files

- **Alerts.json** - Complete alert data with evidence
- Console output with processing statistics

## Future Potential Enhancements

- Integration with a VM Homelab
- Additional detection rules (DDoS, privilege escalation, anomalous behavior)
- Performance optimization for large event volumes
- Machine learning-based anomaly detection
- Integration with SIEM platforms

## License

Read License.md

## Author

Developed by Brandon Le, Computer Science Student at Rutgers University - New Brunswick.

