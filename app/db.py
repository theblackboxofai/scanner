from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any


def parse_modified_at(value: str | None) -> datetime | None:
    if not value:
        return None

    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


class Database:
    def __init__(self, dsn: str, schema_path: Path) -> None:
        self.dsn = dsn
        self.schema_path = schema_path

    def ensure_schema(self) -> None:
        import psycopg

        schema_sql = self.schema_path.read_text(encoding="utf-8")
        with psycopg.connect(self.dsn, autocommit=True) as connection:
            connection.execute(schema_sql)

    def create_scan_run(self, ranges_file: str, masscan_port: int, masscan_rate: int) -> int:
        import psycopg

        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO scan_runs (ranges_file, masscan_port, masscan_rate)
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    (ranges_file, masscan_port, masscan_rate),
                )
                return cursor.fetchone()[0]

    def complete_scan_run(
        self,
        scan_run_id: int,
        discovered_hosts: int,
        saved_hosts: int,
        note: str | None = None,
    ) -> None:
        import psycopg

        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE scan_runs
                    SET completed_at = NOW(),
                        discovered_hosts = %s,
                        saved_hosts = %s,
                        notes = %s
                    WHERE id = %s
                    """,
                    (discovered_hosts, saved_hosts, note, scan_run_id),
                )

    def save_server_scan(
        self,
        scan_run_id: int,
        server_url: str,
        host: str,
        port: int,
        version: str | None,
        response_json: dict[str, Any],
        models: list[dict[str, Any]],
    ) -> int:
        import psycopg
        from psycopg.types.json import Jsonb

        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO server_scans (
                        scan_run_id,
                        server_url,
                        host,
                        port,
                        ollama_version,
                        response_json,
                        model_count
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        scan_run_id,
                        server_url,
                        host,
                        port,
                        version,
                        Jsonb(response_json),
                        len(models),
                    ),
                )
                server_scan_id = cursor.fetchone()[0]

                for model in models:
                    cursor.execute(
                        """
                        INSERT INTO server_models (
                            server_scan_id,
                            name,
                            model,
                            digest,
                            size_bytes,
                            modified_at,
                            details,
                            raw_json
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            server_scan_id,
                            model.get("name") or model.get("model") or "unknown",
                            model.get("model"),
                            model.get("digest"),
                            model.get("size"),
                            parse_modified_at(model.get("modified_at")),
                            Jsonb(model.get("details")),
                            Jsonb(model),
                        ),
                    )

                return server_scan_id
