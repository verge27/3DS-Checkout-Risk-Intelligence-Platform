import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import offline_reports as reports


class ReportTests(unittest.TestCase):
    def test_all_sensitive_and_unrecognised_fields_are_excluded(self):
        secret = 'SYNTHETIC_SECRET_DO_NOT_EXPORT'
        row = {key: secret for key in ['start_url', 'checkout_page_url', 'network_log_summary',
               'screenshots', 'authorization', 'api_key', 'card_number', 'risk_score', 'shodan_vulns',
               'unknown_future_field', secret]}
        row.update(error={'message': secret}, interaction_duration_s=2.5,
                   last_scanned_timestamp='2026-09-10T03:00:00+02:00')
        for fmt in ('json', 'csv'):
            output = reports.render([row], fmt)
            self.assertNotIn(secret, output)
            self.assertNotIn('start_url', output)
        parsed = json.loads(reports.render([row]))
        self.assertEqual(parsed['records'][0]['observed_at'], '2026-09-10T01:00:00Z')
        self.assertEqual(parsed['security_verdict'], 'not_assessed')

    def test_missing_is_unknown_not_zero_or_success(self):
        row = json.loads(reports.render([{}]))['records'][0]
        self.assertIsNone(row['duration_seconds'])
        self.assertIsNone(row['error_recorded'])
        self.assertIsNone(row['observed_at'])

    def test_explicit_zero_and_empty_error_are_preserved(self):
        row = reports.minimise_record({'interaction_duration_s': 0, 'error': ''}, 1)
        self.assertEqual(row['duration_seconds'], 0)
        self.assertIs(row['error_recorded'], False)

    def test_csv_has_exact_allowlist_and_unknowns(self):
        rows = list(csv.DictReader(io.StringIO(reports.render([{}], 'csv'))))
        self.assertEqual(tuple(rows[0]), reports.FIELDS)
        self.assertEqual(rows[0]['observed_at'], 'unknown')

    def test_bad_timestamps_never_echo_source(self):
        for timestamp in ('SYNTHETIC_SECRET', '2026-09-09', '2026-09-09T10:00:00', '=HYPERLINK("secret")'):
            with self.assertRaises(reports.ReportError) as error:
                reports.render([{'last_scanned_timestamp': timestamp}])
            self.assertNotIn(timestamp, str(error.exception))

    def test_invalid_duration_fails(self):
        for duration in (True, -1, float('nan'), float('inf'), 'secret', 10**400):
            with self.assertRaises(reports.ReportError):
                reports.render([{'interaction_duration_s': duration}])

    def test_limit_configuration_rejects_bool_and_invalid_values(self):
        for number in (0, -1, True, 1.5, 10**12):
            with self.assertRaises(reports.ReportError):
                reports.validate_limits(number, 1)
            with self.assertRaises(reports.ReportError):
                reports.validate_limits(1, number)

    def test_strict_input_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            for content in ('{"secret":1}', '[1]', '[{"a":1,"a":2}]', '[{"a":NaN}]', 'SYNTHETIC_SECRET'):
                path.write_text(content, encoding='utf-8')
                with self.assertRaises(reports.ReportError) as error:
                    reports.read_records(path)
                self.assertNotIn('SYNTHETIC_SECRET', str(error.exception))

    def test_bom_json_and_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_text('[{}]', encoding='utf-8-sig')
            self.assertEqual(reports.read_records(path), [{}])
            path.write_text('{}\n\n{}\n', encoding='utf-8')
            self.assertEqual(reports.read_records(path, 'jsonl'), [{}, {}])

    def test_byte_and_record_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_text('[{},{}]', encoding='utf-8')
            with self.assertRaises(reports.ReportError):
                reports.read_records(path, max_bytes=2)
            with self.assertRaises(reports.ReportError):
                reports.read_records(path, max_records=1)
            path.write_text('{}\n{}', encoding='utf-8')
            with self.assertRaises(reports.ReportError):
                reports.read_records(path, 'jsonl', max_records=1)

    def test_existing_output_and_input_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_text('[{}]', encoding='utf-8')
            with self.assertRaises(reports.ReportError):
                reports.write_new(path, 'replacement')
            self.assertEqual(path.read_text(), '[{}]')

    def test_real_cli_isolated_mode_and_failure_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'input.json', Path(directory) / 'output.json'
            source.write_text('[{"error":"SYNTHETIC_SECRET"}]', encoding='utf-8')
            command = [sys.executable, '-I', str(Path(reports.__file__).resolve()), str(source), '--output', str(target)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('SYNTHETIC_SECRET', target.read_text())
            before = target.read_bytes()
            self.assertNotEqual(subprocess.run(command, capture_output=True, timeout=10).returncode, 0)
            self.assertEqual(target.read_bytes(), before)
            source.write_text('SYNTHETIC_SECRET', encoding='utf-8')
            command[-1] = str(Path(directory) / 'failed.json')
            failure = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(failure.returncode, 1)
            self.assertFalse(Path(command[-1]).exists())
            self.assertNotIn('SYNTHETIC_SECRET', failure.stderr)

    def test_network_and_scanner_dependencies_are_not_used(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')):
            payload = reports.render([{'error': 'local fixture'}])
            self.assertTrue(json.loads(payload)['records'][0]['error_recorded'])
        for module in ('scrapy', 'playwright', 'shodan', 'settings', 'spiders'):
            self.assertNotIn(module, sys.modules)


if __name__ == '__main__':
    unittest.main()
