from __future__ import annotations

import logging
import time
from pathlib import Path

import psycopg

from app.config import load_config
from app.db import Database
from app.masscan import run_masscan
from app.ollama import OllamaClient

LOGGER = logging.getLogger(__name__)


def configure_logging(log_level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def execute_scan(config, database: Database, ollama_client: OllamaClient) -> None:
    scan_run_id = database.create_scan_run(
        ranges_file=str(config.ranges_file),
        masscan_port=config.masscan_port,
        masscan_rate=config.masscan_rate,
    )

    discovered_hosts = 0
    saved_hosts = 0
    note = None

    try:
        findings = run_masscan(
            ranges_file=config.ranges_file,
            port=config.masscan_port,
            rate=config.masscan_rate,
            wait_seconds=config.masscan_wait_seconds,
        )
        discovered_hosts = len(findings)
        LOGGER.info("Masscan discovered %s candidate hosts", discovered_hosts)

        for finding in findings:
            snapshot = ollama_client.fetch_snapshot(finding.server_url)
            if snapshot is None:
                continue

            database.save_server_scan(
                scan_run_id=scan_run_id,
                server_url=finding.server_url,
                host=finding.host,
                port=finding.port,
                version=snapshot.version,
                response_json=snapshot.response_json,
                models=snapshot.models,
            )
            saved_hosts += 1
            LOGGER.info(
                "Saved %s models from %s",
                len(snapshot.models),
                finding.server_url,
            )
    except Exception as exc:
        note = str(exc)
        LOGGER.exception("Scan run failed")
    finally:
        database.complete_scan_run(
            scan_run_id=scan_run_id,
            discovered_hosts=discovered_hosts,
            saved_hosts=saved_hosts,
            note=note,
        )


def initialize_database(config, database: Database) -> None:
    while True:
        try:
            database.ensure_schema()
            return
        except psycopg.OperationalError as exc:
            LOGGER.error("Database connection failed for %s: %s", config.database_url, exc)
            LOGGER.info(
                "Retrying database connection in %s seconds",
                config.db_connect_retry_seconds,
            )
            time.sleep(config.db_connect_retry_seconds)


def main() -> None:
    config = load_config()
    configure_logging(config.log_level)

    database = Database(
        dsn=config.database_url,
        schema_path=Path(__file__).resolve().parent.parent / "sql" / "schema.sql",
    )
    initialize_database(config, database)

    ollama_client = OllamaClient(
        user_agent=config.user_agent,
        timeout_seconds=config.request_timeout_seconds,
    )

    while True:
        execute_scan(config, database, ollama_client)
        if config.run_once:
            return

        LOGGER.info("Sleeping for %s seconds before the next scan", config.scan_interval_seconds)
        time.sleep(config.scan_interval_seconds)


if __name__ == "__main__":
    main()
