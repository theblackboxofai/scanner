import unittest
from datetime import datetime, timezone

from app.db import parse_modified_at


class DatabaseHelpersTest(unittest.TestCase):
    def test_parse_modified_at_accepts_utc_suffix(self) -> None:
        parsed = parse_modified_at("2025-01-01T00:00:00Z")

        self.assertEqual(parsed, datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc))

    def test_parse_modified_at_returns_none_for_empty_values(self) -> None:
        self.assertIsNone(parse_modified_at(None))
        self.assertIsNone(parse_modified_at(""))


if __name__ == "__main__":
    unittest.main()
