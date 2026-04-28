"""
tests/test_parser.py — Unit tests for the log line parser.

Run:
    python -m pytest tests/ -v
"""

import pytest
from datetime import timezone
from detector.parser import parse_line, LogEntry, ParseFailure


# ---------------------------------------------------------------------------
# Fixtures — representative log lines
# ---------------------------------------------------------------------------

GOOD_LINE = (
    '{"source_ip":"192.168.1.10","timestamp":"28/Apr/2025:12:00:00 +0000",'
    '"method":"GET","path":"/index.php","status":200,"response_size":4096}'
)

GOOD_LINE_ISO = (
    '{"source_ip":"10.0.0.1","timestamp":"2025-04-28T12:00:00Z",'
    '"method":"POST","path":"/remote.php/dav","status":201,"response_size":0}'
)

LINE_304_DASH_SIZE = (
    '{"source_ip":"192.168.1.5","timestamp":"28/Apr/2025:12:01:00 +0000",'
    '"method":"GET","path":"/favicon.ico","status":304,"response_size":"-"}'
)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestHappyPath:

    def test_parses_valid_line(self):
        result = parse_line(GOOD_LINE)
        assert isinstance(result, LogEntry)
        assert result.source_ip == "192.168.1.10"
        assert result.status == 200
        assert result.method == "GET"
        assert result.path == "/index.php"
        assert result.response_size == 4096

    def test_timestamp_is_utc_aware(self):
        result = parse_line(GOOD_LINE)
        assert isinstance(result, LogEntry)
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.tzinfo == timezone.utc

    def test_iso_timestamp_parsed(self):
        result = parse_line(GOOD_LINE_ISO)
        assert isinstance(result, LogEntry)
        assert result.source_ip == "10.0.0.1"
        assert result.status == 201

    def test_method_normalized_to_uppercase(self):
        line = GOOD_LINE.replace('"GET"', '"get"')
        result = parse_line(line)
        assert isinstance(result, LogEntry)
        assert result.method == "GET"

    def test_dash_response_size_becomes_zero(self):
        result = parse_line(LINE_304_DASH_SIZE)
        assert isinstance(result, LogEntry)
        assert result.response_size == 0

    def test_status_as_string_coerced(self):
        line = GOOD_LINE.replace('"status":200', '"status":"200"')
        result = parse_line(line)
        assert isinstance(result, LogEntry)
        assert result.status == 200

    def test_raw_line_preserved(self):
        result = parse_line(GOOD_LINE)
        assert isinstance(result, LogEntry)
        assert result.raw == GOOD_LINE


# ---------------------------------------------------------------------------
# Malformed JSON
# ---------------------------------------------------------------------------

class TestMalformedJSON:

    def test_empty_line_returns_failure(self):
        result = parse_line("")
        assert isinstance(result, ParseFailure)
        assert "empty" in result.reason

    def test_whitespace_only_line(self):
        result = parse_line("   \n  ")
        assert isinstance(result, ParseFailure)

    def test_truncated_json(self):
        result = parse_line('{"source_ip":"1.2.3.4","timestamp":')
        assert isinstance(result, ParseFailure)
        assert "json_decode_error" in result.reason

    def test_plain_text_line(self):
        result = parse_line("192.168.1.1 - - [28/Apr/2025] GET / 200")
        assert isinstance(result, ParseFailure)

    def test_json_array_not_object(self):
        result = parse_line('[1, 2, 3]')
        assert isinstance(result, ParseFailure)
        assert "expected_json_object" in result.reason

    def test_json_null(self):
        result = parse_line('null')
        assert isinstance(result, ParseFailure)


# ---------------------------------------------------------------------------
# Missing fields
# ---------------------------------------------------------------------------

class TestMissingFields:

    def test_missing_source_ip(self):
        line = (
            '{"timestamp":"28/Apr/2025:12:00:00 +0000",'
            '"method":"GET","path":"/","status":200,"response_size":100}'
        )
        result = parse_line(line)
        assert isinstance(result, ParseFailure)
        assert "missing_fields" in result.reason

    def test_missing_status(self):
        line = (
            '{"source_ip":"1.2.3.4","timestamp":"28/Apr/2025:12:00:00 +0000",'
            '"method":"GET","path":"/","response_size":100}'
        )
        result = parse_line(line)
        assert isinstance(result, ParseFailure)

    def test_all_fields_missing(self):
        result = parse_line('{}')
        assert isinstance(result, ParseFailure)
        assert "missing_fields" in result.reason


# ---------------------------------------------------------------------------
# Invalid field values
# ---------------------------------------------------------------------------

class TestInvalidFieldValues:

    def test_status_out_of_range_low(self):
        line = GOOD_LINE.replace('"status":200', '"status":99')
        result = parse_line(line)
        assert isinstance(result, ParseFailure)
        assert "invalid_status" in result.reason

    def test_status_out_of_range_high(self):
        line = GOOD_LINE.replace('"status":200', '"status":600')
        result = parse_line(line)
        assert isinstance(result, ParseFailure)

    def test_unparseable_timestamp(self):
        line = GOOD_LINE.replace(
            '"28/Apr/2025:12:00:00 +0000"', '"not-a-date"'
        )
        result = parse_line(line)
        assert isinstance(result, ParseFailure)
        assert "invalid_timestamp" in result.reason

    def test_null_source_ip(self):
        line = GOOD_LINE.replace('"192.168.1.10"', 'null')
        result = parse_line(line)
        assert isinstance(result, ParseFailure)

    def test_empty_path(self):
        line = GOOD_LINE.replace('"/index.php"', '""')
        result = parse_line(line)
        assert isinstance(result, ParseFailure)

    def test_negative_response_size_clamped_to_zero(self):
        line = GOOD_LINE.replace('"response_size":4096', '"response_size":-100')
        result = parse_line(line)
        assert isinstance(result, LogEntry)
        assert result.response_size == 0


# ---------------------------------------------------------------------------
# Line number propagation
# ---------------------------------------------------------------------------

class TestLineNumber:

    def test_line_num_in_failure(self):
        result = parse_line("{}", line_num=42)
        assert isinstance(result, ParseFailure)
        assert result.line_num == 42

    def test_line_num_not_in_success(self):
        result = parse_line(GOOD_LINE, line_num=7)
        assert isinstance(result, LogEntry)  # LogEntry has no line_num by design
