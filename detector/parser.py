"""
parser.py — Safe JSON log line parser for Nginx JSON-format access logs.

Responsibilities:
  - Parse a raw log line string into a typed LogEntry dataclass
  - Never raise on malformed input — always returns a result or None
  - Validate that required fields are present and have sane types
  - Normalize fields (IP string, datetime, int status, etc.)

Does NOT perform any IO — pure data transformation.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LogEntry:
    """
    Typed representation of one parsed Nginx log line.

    All fields that could be missing or malformed are Optional.
    Consumers must check for None before using optional fields.
    """
    source_ip:     str
    timestamp:     datetime
    method:        str
    path:          str
    status:        int
    response_size: int

    # Raw line preserved for debugging and dead-letter logging
    raw: str = field(compare=False, repr=False)


@dataclass(frozen=True)
class ParseFailure:
    """
    Returned instead of LogEntry when a line cannot be parsed.

    Carries enough context to debug the problem without logging
    the full raw line at ERROR level on every bad line.
    """
    reason:   str
    raw_line: str
    line_num: Optional[int] = None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

# Fields that MUST be present for a line to be useful downstream
REQUIRED_FIELDS = {"source_ip", "timestamp", "method", "path", "status", "response_size"}

# Acceptable timestamp formats from Nginx (in order of likelihood)
TIMESTAMP_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",   # 28/Apr/2025:12:34:56 +0000  (nginx default)
    "%Y-%m-%dT%H:%M:%S%z",    # 2025-04-28T12:34:56+00:00   (ISO 8601)
    "%Y-%m-%dT%H:%M:%SZ",     # 2025-04-28T12:34:56Z
    "%Y-%m-%d %H:%M:%S",      # 2025-04-28 12:34:56          (no tz → UTC assumed)
]


def parse_line(raw_line: str, line_num: Optional[int] = None) -> LogEntry | ParseFailure:
    """
    Parse one raw log line into a LogEntry or a ParseFailure.

    Never raises. All exceptions are caught and returned as ParseFailure.

    Args:
        raw_line:  The raw string from the log file (newline already stripped).
        line_num:  Optional line counter for tracing failures in context.

    Returns:
        LogEntry on success, ParseFailure on any error.
    """
    stripped = raw_line.strip()

    if not stripped:
        return ParseFailure(reason="empty_line", raw_line=raw_line, line_num=line_num)

    # -----------------------------------------------------------------------
    # Step 1: JSON decode
    # -----------------------------------------------------------------------
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        return ParseFailure(
            reason=f"json_decode_error: {exc.msg} at pos {exc.pos}",
            raw_line=raw_line,
            line_num=line_num,
        )
    except Exception as exc:
        # Catch anything unexpected (e.g. MemoryError on gigantic line)
        return ParseFailure(
            reason=f"unexpected_json_error: {type(exc).__name__}",
            raw_line=raw_line,
            line_num=line_num,
        )

    if not isinstance(data, dict):
        return ParseFailure(
            reason=f"expected_json_object_got_{type(data).__name__}",
            raw_line=raw_line,
            line_num=line_num,
        )

    # -----------------------------------------------------------------------
    # Step 2: Required field presence check
    # -----------------------------------------------------------------------
    missing = REQUIRED_FIELDS - data.keys()
    if missing:
        return ParseFailure(
            reason=f"missing_fields: {sorted(missing)}",
            raw_line=raw_line,
            line_num=line_num,
        )

    # -----------------------------------------------------------------------
    # Step 3: Field-level type coercion and validation
    # -----------------------------------------------------------------------

    # source_ip — must be a non-empty string
    source_ip = _coerce_string(data, "source_ip")
    if source_ip is None:
        return ParseFailure(
            reason="invalid_source_ip: not a string or empty",
            raw_line=raw_line,
            line_num=line_num,
        )

    # timestamp — try multiple formats; store as UTC-aware datetime
    timestamp = _parse_timestamp(data.get("timestamp"))
    if timestamp is None:
        return ParseFailure(
            reason=f"invalid_timestamp: could not parse '{data.get('timestamp')}'",
            raw_line=raw_line,
            line_num=line_num,
        )

    # method — must be a non-empty string
    method = _coerce_string(data, "method")
    if method is None:
        return ParseFailure(
            reason="invalid_method: not a string or empty",
            raw_line=raw_line,
            line_num=line_num,
        )

    # path — must be a non-empty string
    path = _coerce_string(data, "path")
    if path is None:
        return ParseFailure(
            reason="invalid_path: not a string or empty",
            raw_line=raw_line,
            line_num=line_num,
        )

    # status — must coerce to int in 100–599
    status = _coerce_int(data, "status")
    if status is None or not (100 <= status <= 599):
        return ParseFailure(
            reason=f"invalid_status: '{data.get('status')}' not in 100-599",
            raw_line=raw_line,
            line_num=line_num,
        )

    # response_size — must coerce to non-negative int ("-" maps to 0)
    response_size = _coerce_response_size(data.get("response_size"))
    if response_size is None:
        return ParseFailure(
            reason=f"invalid_response_size: '{data.get('response_size')}'",
            raw_line=raw_line,
            line_num=line_num,
        )

    # -----------------------------------------------------------------------
    # Step 4: Construct entry
    # -----------------------------------------------------------------------
    return LogEntry(
        source_ip=source_ip,
        timestamp=timestamp,
        method=method.upper(),
        path=path,
        status=status,
        response_size=response_size,
        raw=raw_line,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _coerce_string(data: dict, key: str) -> Optional[str]:
    val = data.get(key)
    if not isinstance(val, str) or not val.strip():
        # Accept int/float that stringifies sensibly (e.g. numeric IPs in some loggers)
        if isinstance(val, (int, float)):
            return str(val)
        return None
    return val.strip()


def _coerce_int(data: dict, key: str) -> Optional[int]:
    val = data.get(key)
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        return int(val)
    if isinstance(val, str):
        try:
            return int(val.strip())
        except ValueError:
            return None
    return None


def _coerce_response_size(val) -> Optional[int]:
    """Nginx logs '-' for zero-size responses (e.g. 304s)."""
    if val == "-" or val is None:
        return 0
    if isinstance(val, int):
        return max(0, val)
    if isinstance(val, float):
        return max(0, int(val))
    if isinstance(val, str):
        stripped = val.strip()
        if stripped == "-":
            return 0
        try:
            return max(0, int(stripped))
        except ValueError:
            return None
    return None


def _parse_timestamp(raw_ts) -> Optional[datetime]:
    if not isinstance(raw_ts, str) or not raw_ts.strip():
        return None

    raw_ts = raw_ts.strip()

    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(raw_ts, fmt)
            # If parsed without timezone, assume UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    return None
