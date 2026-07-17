import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = "demo-output"
DEFAULT_SEED = 42
DEFAULT_BASE_TIME = "2026-07-15T12:00:00Z"
DEFAULT_TOP_N = 5
GSON_VERSION = "2.10.1"


SCENARIOS = ("all", "brute-force", "port-scan", "dns-tunnel", "icmp-sweep", "syn-flood")


def scenario_options(scenario: str) -> dict[str, int]:
    base = {
        "normal": 100,
        "attacks": 0,
        "attempts_per_attack": 5,
        "portscans": 0,
        "ports_per_scan": 30,
        "dnsattacks": 0,
        "dns_queries_per_attack": 6,
        "icmpsweeps": 0,
        "icmp_targets_per_sweep": 30,
        "synfloods": 0,
        "syn_packets_per_flood": 80,
        "acks_per_flood": 5,
    }

    if scenario == "all":
        base.update({
            "attacks": 1,
            "portscans": 1,
            "dnsattacks": 1,
            "icmpsweeps": 1,
            "synfloods": 1,
        })
    elif scenario == "brute-force":
        base["attacks"] = 1
    elif scenario == "port-scan":
        base["portscans"] = 1
    elif scenario == "dns-tunnel":
        base["dnsattacks"] = 1
    elif scenario == "icmp-sweep":
        base["icmpsweeps"] = 1
    elif scenario == "syn-flood":
        base["synfloods"] = 1
    else:
        raise ValueError(f"unsupported scenario: {scenario}")

    return base


def project_relative_path(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def resolve_rules_path(path_value: str | None) -> Path | None:
    if path_value is None:
        return None

    candidate = Path(path_value)
    candidates = [candidate]
    if not candidate.is_absolute():
        candidates.append(PROJECT_ROOT / candidate)

    for path in candidates:
        if path.exists():
            return path.resolve()

    raise FileNotFoundError(f"Rule config file not found: {path_value}")


def gson_jar_path(home: Path | None = None) -> Path:
    home_dir = home or Path.home()
    return (
        home_dir
        / ".m2"
        / "repository"
        / "com"
        / "google"
        / "code"
        / "gson"
        / "gson"
        / GSON_VERSION
        / f"gson-{GSON_VERSION}.jar"
    )


def java_classpath(home: Path | None = None) -> str:
    entries = [PROJECT_ROOT / "target" / "classes", gson_jar_path(home)]
    return os.pathsep.join(str(entry.resolve()) for entry in entries)


def build_generator_command(
    events_path: Path,
    scenario: str,
    seed: int,
    base_time: str,
    verbose: bool = False,
) -> list[str]:
    command = [
        sys.executable,
        str(PROJECT_ROOT / "python" / "log_generator.py"),
        "--output",
        str(events_path),
        "--output_format",
        "json",
        "--seed",
        str(seed),
        "--base_time",
        base_time,
    ]

    for key, value in scenario_options(scenario).items():
        command.extend([f"--{key}", str(value)])

    if verbose:
        command.append("--verbose")

    return command


def build_java_command(events_path: Path, rules_path: Path | None = None) -> list[str]:
    command = [
        "java",
        "-cp",
        java_classpath(),
        "com.ids.IDSCore",
        str(events_path.resolve()),
    ]
    if rules_path is not None:
        command.append(str(rules_path.resolve()))
    return command


def build_report_command(alerts_path: Path, report_path: Path, top_n: int, verbose: bool = False) -> list[str]:
    command = [
        sys.executable,
        str(PROJECT_ROOT / "python" / "report_generator.py"),
        "--input",
        str(alerts_path),
        "--format",
        "html",
        "--output",
        str(report_path),
        "--top_n",
        str(top_n),
    ]
    if verbose:
        command.append("--verbose")
    return command


def build_compile_command() -> list[str]:
    return [resolve_executable("mvn"), "compile"]


def resolve_executable(name: str) -> str:
    if os.name == "nt":
        for candidate in (f"{name}.cmd", f"{name}.exe", name):
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
    resolved = shutil.which(name)
    return resolved or name


def command_to_string(command: list[str]) -> str:
    return " ".join(quote_arg(part) for part in command)


def quote_arg(value: str) -> str:
    if not value or any(char.isspace() for char in value):
        return f'"{value}"'
    return value


def run_command(command: list[str], label: str, cwd: Path) -> None:
    print(f"\n[{label}]", flush=True)
    print(command_to_string(command), flush=True)
    subprocess.run(command, cwd=str(cwd), check=True, stderr=subprocess.STDOUT)


def run_demo(args: argparse.Namespace) -> int:
    output_dir = project_relative_path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    events_path = output_dir / "Events.json"
    alerts_path = output_dir / "Alerts.json"
    report_path = output_dir / "report.html"
    rules_path = resolve_rules_path(args.rules)

    generator_command = build_generator_command(
        events_path,
        args.scenario,
        args.seed,
        args.base_time,
        args.verbose,
    )
    compile_command = build_compile_command()
    java_command = build_java_command(events_path, rules_path)
    report_command = build_report_command(alerts_path, report_path, args.top_n, args.verbose)

    try:
        run_command(generator_command, "Generate events", PROJECT_ROOT)
        if not args.skip_compile:
            run_command(compile_command, "Compile Java", PROJECT_ROOT)

        missing_gson = gson_jar_path()
        if not missing_gson.exists():
            raise FileNotFoundError(
                "Gson dependency was not found after compile: "
                + str(missing_gson)
                + ". Run 'mvn compile' and confirm Maven can download dependencies."
            )

        run_command(java_command, "Run IDS", output_dir)
        run_command(report_command, "Generate HTML report", PROJECT_ROOT)
    except FileNotFoundError as exc:
        print(f"\nDemo failed: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"\nDemo failed while running command: {command_to_string(exc.cmd)}", file=sys.stderr)
        print(f"Exit code: {exc.returncode}", file=sys.stderr)
        return exc.returncode or 1

    print("\nDemo complete.", flush=True)
    print(f"Scenario: {args.scenario}", flush=True)
    if rules_path is not None:
        print(f"Rule config: {rules_path}", flush=True)
    else:
        print("Rule config: built-in defaults", flush=True)
    print(f"Events: {events_path}", flush=True)
    print(f"Alerts: {alerts_path}", flush=True)
    print(f"HTML report: {report_path}", flush=True)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the IDS demo pipeline: generate events, run IDS, and create an HTML report."
    )
    parser.add_argument("--scenario", choices=SCENARIOS, default="all", help="Demo scenario to generate.")
    parser.add_argument("--rules", help="Optional JSON rule config path for built-in rule thresholds.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory for demo artifacts.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Seed for reproducible event generation.")
    parser.add_argument("--base-time", default=DEFAULT_BASE_TIME, help="UTC ISO-8601 base time for generated events.")
    parser.add_argument("--top-n", type=int, default=DEFAULT_TOP_N, help="Number of alert examples/top values in report.")
    parser.add_argument("--skip-compile", action="store_true", help="Skip mvn compile for faster reruns.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose generator/report logging.")
    return parser.parse_args()


def main() -> int:
    return run_demo(parse_args())


if __name__ == "__main__":
    sys.exit(main())
