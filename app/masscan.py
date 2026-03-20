from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MasscanFinding:
    host: str
    port: int
    server_url: str


def build_server_url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def parse_masscan_output(output: str, expected_port: int) -> list[MasscanFinding]:
    findings: dict[tuple[str, int], MasscanFinding] = {}

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 4 or parts[0] != "open" or parts[1] != "tcp":
            continue

        try:
            port = int(parts[2])
        except ValueError:
            continue

        host = parts[3]
        if port != expected_port:
            continue

        findings[(host, port)] = MasscanFinding(
            host=host,
            port=port,
            server_url=build_server_url(host, port),
        )

    return sorted(findings.values(), key=lambda item: (item.host, item.port))


def run_masscan(
    ranges_file: Path,
    port: int,
    rate: int,
    wait_seconds: int,
) -> list[MasscanFinding]:
    if not ranges_file.exists():
        raise FileNotFoundError(f"Ranges file does not exist: {ranges_file}")

    command = [
        "masscan",
        "-p",
        str(port),
        "-iL",
        str(ranges_file),
        "--rate",
        str(rate),
        "--wait",
        str(wait_seconds),
        "-oL",
        "-",
    ]

    completed = subprocess.run(
        command,
        capture_output=True,
        check=False,
        text=True,
    )

    if completed.returncode != 0:
        stderr = completed.stderr.strip() or "masscan exited with a non-zero status"
        raise RuntimeError(stderr)

    return parse_masscan_output(completed.stdout, expected_port=port)
