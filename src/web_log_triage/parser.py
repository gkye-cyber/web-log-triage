from dataclasses import dataclass
from datetime import datetime
from typing import Generator, Optional
import re
import urllib.parse
from pathlib import Path

@dataclass
class LogEntry:
    ip: str
    timestamp: Optional[datetime]
    method: str
    raw_uri: str
    decoded_uri: str # unqouted with urllib.parse.unqoute
    protocol: str
    status_code: int
    response_size: int
    referrer: str
    user_agent: str
    raw_line: str

combined_log_regex = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+(?P<protocol>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# parsing log timestamp str into datetime
def _parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

# parsing log line into LogEntry
def parse_log_line(line: str) -> Optional[LogEntry]:
    line = line.strip() # strip leading/trailing whitespace
    match = combined_log_regex.match(line)
    if not match:
        return None

    ip = match.group("ip")
    timestamp = _parse_timestamp(match.group("timestamp"))
    method = match.group("method")
    raw_uri = match.group("uri")
    decoded_uri = urllib.parse.unquote(raw_uri)
    protocol = match.group("protocol") or ""
    status_code = int(match.group("status"))
    raw_size = match.group("size")
    response_size = int(raw_size) if raw_size.isdigit() else 0 # int conversion with fallback to 0 if not a digit
    referrer = match.group("referrer") or ""
    user_agent = match.group("user_agent") or ""
    raw_line = line

    return LogEntry(
        ip=ip,
        timestamp=timestamp,
        method=method,
        raw_uri=raw_uri,
        decoded_uri=decoded_uri,
        protocol=protocol,
        status_code=status_code,
        response_size=response_size,
        referrer=referrer,
        user_agent=user_agent,
        raw_line=raw_line
    )

# func to parse log file into LogEntry generator
def parse_file(file_path: Path | str) -> Generator[LogEntry, None, None]:
    file_path = Path(file_path)
    with file_path.open("r", encoding="utf-8", errors="replace") as f: # errors="replace" to handle invalid utf-8 characters
        for line in f:
            log_entry = parse_log_line(line)
            if log_entry:
                yield log_entry