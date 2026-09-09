"""Privacy-minimised exports of existing local reports. Never runs a scanner.

The allowlist deliberately excludes target identities, free text, payment data,
network logs, screenshots, vulnerability fields and risk scores. Missing fields
stay unknown. Exports are not findings about payment security or scan success.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import io
import json
import math
import os
from pathlib import Path
import sys

DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_RECORDS = 10_000
FIELDS = ('record_number', 'observed_at', 'duration_seconds', 'error_recorded')


class ReportError(ValueError):
    """A safe diagnostic that never contains raw report data."""


def validate_limits(max_bytes, max_records):
    for name, value, ceiling in [('max_bytes', max_bytes, 64 * 1024 * 1024),
                                 ('max_records', max_records, 100_000)]:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= ceiling:
            raise ReportError(f'{name} must be an integer between 1 and {ceiling}')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReportError('Duplicate JSON key; input is ambiguous')
        result[key] = value
    return result


def _nonfinite(value):
    raise ReportError('Non-finite JSON number is not permitted')


def _decode(text):
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        if isinstance(error, ReportError):
            raise
        raise ReportError('Invalid JSON; original content omitted') from None


def read_records(path, input_format='json', max_bytes=DEFAULT_MAX_BYTES,
                 max_records=DEFAULT_MAX_RECORDS):
    validate_limits(max_bytes, max_records)
    if input_format not in ('json', 'jsonl'):
        raise ReportError('input_format must be json or jsonl')
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file():
            raise ReportError('Input must be a regular, non-symlink local file')
        with path.open('rb') as stream:
            raw = stream.read(max_bytes + 1)
    except OSError:
        raise ReportError('Cannot read input file') from None
    if len(raw) > max_bytes:
        raise ReportError('Input exceeds byte limit')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise ReportError('Input must be UTF-8') from None
    if input_format == 'json':
        records = _decode(text)
        if not isinstance(records, list):
            raise ReportError('JSON report must be an array of objects')
    else:
        records = []
        for line in text.splitlines():
            if line.strip():
                if len(records) >= max_records:
                    raise ReportError('Input exceeds record limit')
                records.append(_decode(line))
    if len(records) > max_records:
        raise ReportError('Input exceeds record limit')
    if any(not isinstance(row, dict) for row in records):
        raise ReportError('Every report record must be an object')
    return records


def _timestamp(value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise ReportError('Invalid observation timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError('Timezone required')
        return parsed.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    except (ValueError, OverflowError):
        raise ReportError('Observation timestamp must be ISO 8601 with timezone') from None


def minimise_record(record, number):
    if not isinstance(record, dict):
        raise ReportError('Report record must be an object')
    duration = record.get('interaction_duration_s')
    if duration is not None and (isinstance(duration, bool) or not isinstance(duration, (int, float))):
        raise ReportError('Duration must be a finite, non-negative number or null')
    try:
        if duration is not None and (not math.isfinite(duration) or duration < 0):
            raise ReportError('Duration must be a finite, non-negative number or null')
    except OverflowError:
        raise ReportError('Duration is too large') from None
    error = record.get('error')
    if error is not None and not isinstance(error, (str, dict, list)):
        raise ReportError('Error field has an unsupported type')
    return {
        'record_number': number,
        'observed_at': _timestamp(record.get('last_scanned_timestamp')),
        'duration_seconds': duration,
        # Null/missing is unknown, not proof that an operation succeeded.
        'error_recorded': None if error is None else bool(error),
    }


def render(records, output_format='json'):
    if output_format not in ('json', 'csv'):
        raise ReportError('output_format must be json or csv')
    rows = []
    for number, record in enumerate(records, 1):
        try:
            rows.append(minimise_record(record, number))
        except ReportError as error:
            raise ReportError(f'Record {number}: {error}') from None
    if output_format == 'json':
        return json.dumps({'schema_version': 1, 'scope': 'operational_metadata_only',
                           'security_verdict': 'not_assessed', 'record_count': len(rows),
                           'records': rows}, ensure_ascii=False, allow_nan=False, indent=2) + '\n'
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=FIELDS, lineterminator='\n')
    writer.writeheader()
    for row in rows:
        writer.writerow({key: 'unknown' if value is None else value for key, value in row.items()})
    return out.getvalue()


def write_new(path, payload):
    """Create an owner-readable export without replacing any existing pathname."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        raise ReportError('Cannot create output; choose a new file in an existing directory') from None
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        # Do not imply success or delete a path that another process may have replaced.
        raise ReportError('Output write failed; a partial output file may remain') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description='Export operational metadata from a LOCAL report; no scanning or network access')
    parser.add_argument('input', type=Path)
    parser.add_argument('--input-format', choices=['json', 'jsonl'], default='json')
    parser.add_argument('--format', choices=['json', 'csv'], default='json')
    parser.add_argument('--output', type=Path, help='New file only; defaults to stdout')
    parser.add_argument('--max-bytes', type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument('--max-records', type=int, default=DEFAULT_MAX_RECORDS)
    args = parser.parse_args(argv)
    try:
        records = read_records(args.input, args.input_format, args.max_bytes, args.max_records)
        payload = render(records, args.format)
        if args.output:
            write_new(args.output, payload)
        else:
            sys.stdout.write(payload)
        return 0
    except (ReportError, OSError) as error:
        message = str(error) if isinstance(error, ReportError) else 'Output could not be written'
        print(f'error: {message}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
