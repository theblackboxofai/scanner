from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import requests

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class OllamaSnapshot:
    server_url: str
    version: str | None
    response_json: dict[str, Any]
    models: list[dict[str, Any]]


class OllamaClient:
    def __init__(self, user_agent: str, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds
        self.headers = {
            "Accept": "application/json",
            "User-Agent": user_agent,
        }

    def fetch_snapshot(self, server_url: str) -> OllamaSnapshot | None:
        with requests.Session() as session:
            session.headers.update(self.headers)

            try:
                response = session.get(
                    f"{server_url}/api/tags",
                    timeout=self.timeout_seconds,
                )
                response.raise_for_status()
            except requests.RequestException as exc:
                LOGGER.warning("Failed to fetch models from %s: %s", server_url, exc)
                return None

            try:
                payload = response.json()
            except ValueError:
                LOGGER.warning("Non-JSON response from %s/api/tags", server_url)
                return None

            if not isinstance(payload, dict):
                LOGGER.warning("Unexpected JSON shape from %s/api/tags", server_url)
                return None

            models = payload.get("models")
            if not isinstance(models, list) or not models:
                LOGGER.info("No models returned by %s", server_url)
                return None

            version = self._fetch_version(server_url, session)

            return OllamaSnapshot(
                server_url=server_url,
                version=version,
                response_json=payload,
                models=models,
            )

    def _fetch_version(self, server_url: str, session: requests.Session) -> str | None:
        try:
            response = session.get(
                f"{server_url}/api/version",
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError):
            return None

        if not isinstance(payload, dict):
            return None

        version = payload.get("version")
        if isinstance(version, str) and version:
            return version
        return None
