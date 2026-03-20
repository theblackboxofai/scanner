from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _get_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return int(raw_value)


def _get_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return float(raw_value)


def _get_bool(name: str, default: bool = False) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    database_url: str
    db_connect_retry_seconds: int
    ranges_file: Path
    masscan_port: int
    masscan_rate: int
    masscan_wait_seconds: int
    request_timeout_seconds: float
    scan_interval_seconds: int
    user_agent: str
    run_once: bool
    log_level: str


def load_config() -> Config:
    return Config(
        database_url=os.getenv(
            "DATABASE_URL",
            "postgresql://blackbox:blackbox@postgres:5432/blackbox",
        ),
        db_connect_retry_seconds=_get_int("DB_CONNECT_RETRY_SECONDS", 30),
        ranges_file=Path(os.getenv("RANGES_FILE", "/app/ranges.txt")),
        masscan_port=_get_int("MASSCAN_PORT", 11434),
        masscan_rate=_get_int("MASSCAN_RATE", 1000),
        masscan_wait_seconds=_get_int("MASSCAN_WAIT_SECONDS", 10),
        request_timeout_seconds=_get_float("REQUEST_TIMEOUT_SECONDS", 15.0),
        scan_interval_seconds=_get_int("SCAN_INTERVAL_SECONDS", 86400),
        user_agent=os.getenv("HTTP_USER_AGENT", "Blackbox/1.0"),
        run_once=_get_bool("RUN_ONCE", False),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
    )
