import unittest

from app.masscan import MasscanFinding, build_server_url, parse_masscan_output


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


if __name__ == "__main__":
    unittest.main()
