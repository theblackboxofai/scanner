from __future__ import annotations

import logging
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

LOGGER = logging.getLogger(__name__)


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


def _consume_stream(
    stream: TextIO,
    sink: list[str],
    line_handler: Callable[[str], None],
) -> None:
    for raw_line in stream:
        sink.append(raw_line)
        line_handler(raw_line.rstrip())

    stream.close()


def _log_stdout_line(line: str, expected_port: int) -> None:
    if not line:
        return

    parts = line.split()
    if len(parts) >= 4 and parts[0] == "open" and parts[1] == "tcp":
        try:
            discovered_port = int(parts[2])
        except ValueError:
            LOGGER.debug("masscan stdout: %s", line)
            return

        if discovered_port == expected_port:
            LOGGER.info("Masscan found %s:%s", parts[3], discovered_port)
            return

    LOGGER.debug("masscan stdout: %s", line)


def _log_stderr_line(line: str) -> None:
    if not line:
        return

    LOGGER.info("masscan: %s", line)


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

    LOGGER.info(
        "Starting masscan for %s on port %s with rate %s",
        ranges_file,
        port,
        rate,
    )

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if process.stdout is None or process.stderr is None:
        raise RuntimeError("masscan did not expose stdout/stderr streams")

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    stdout_thread = threading.Thread(
        target=_consume_stream,
        args=(process.stdout, stdout_chunks, lambda line: _log_stdout_line(line, port)),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_consume_stream,
        args=(process.stderr, stderr_chunks, _log_stderr_line),
        daemon=True,
    )

    stdout_thread.start()
    stderr_thread.start()

    returncode = process.wait()
    stdout_thread.join()
    stderr_thread.join()

    stdout = "".join(stdout_chunks)
    stderr = "".join(stderr_chunks).strip()

    if returncode != 0:
        stderr = stderr or "masscan exited with a non-zero status"
        raise RuntimeError(stderr)

    return parse_masscan_output(stdout, expected_port=port)
