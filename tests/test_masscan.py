import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.masscan import MasscanFinding, build_server_url, parse_masscan_output, run_masscan


class MasscanParserTest(unittest.TestCase):
    def test_parse_masscan_output_filters_and_deduplicates_hosts(self) -> None:
        output = """
        #masscan
        open tcp 11434 10.0.0.5 1742460000
        open tcp 11434 10.0.0.5 1742460001
        open tcp 80 10.0.0.6 1742460002
        open tcp 11434 10.0.0.7 1742460003
        """

        findings = parse_masscan_output(output, expected_port=11434)

        self.assertEqual(
            findings,
            [
                MasscanFinding("10.0.0.5", 11434, build_server_url("10.0.0.5", 11434)),
                MasscanFinding("10.0.0.7", 11434, build_server_url("10.0.0.7", 11434)),
            ],
        )

    @mock.patch("app.masscan.subprocess.Popen")
    def test_run_masscan_logs_progress_while_collecting_output(self, mock_popen: mock.Mock) -> None:
        class FakeProcess:
            def __init__(self, stdout_text: str, stderr_text: str, returncode: int = 0) -> None:
                self.stdout = io.StringIO(stdout_text)
                self.stderr = io.StringIO(stderr_text)
                self.returncode = returncode

            def wait(self) -> int:
                return self.returncode

        mock_popen.return_value = FakeProcess(
            stdout_text="open tcp 11434 10.0.0.5 1742460000\n",
            stderr_text="rate: 1000-kpps, 10.00% done, waiting 9-secs\n",
        )

        with tempfile.NamedTemporaryFile() as ranges_file:
            with self.assertLogs("app.masscan", level="INFO") as captured_logs:
                findings = run_masscan(
                    ranges_file=Path(ranges_file.name),
                    port=11434,
                    rate=1000,
                    wait_seconds=10,
                )

        self.assertEqual(
            findings,
            [MasscanFinding("10.0.0.5", 11434, build_server_url("10.0.0.5", 11434))],
        )
        self.assertTrue(any("Starting masscan" in message for message in captured_logs.output))
        self.assertTrue(any("Masscan found 10.0.0.5:11434" in message for message in captured_logs.output))
        self.assertTrue(any("rate: 1000-kpps" in message for message in captured_logs.output))


if __name__ == "__main__":
    unittest.main()
