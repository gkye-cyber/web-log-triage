"""Automated Web Server Access Log Threat Hunter & Forensic Triage Tool."""

__version__ = "0.1.0"

from web_log_triage.parser import LogEntry, parse_log_line, parse_file
from web_log_triage.detector import ThreatDetector, ThreatMatch, SignatureRule
from web_log_triage.enricher import IPEnricher, IPEnrichment, enrich_ips
from web_log_triage.reporter import (
    ForensicReport,
    build_forensic_report,
    generate_json_report,
    generate_html_report,
)

__all__ = [
    "__version__",
    "LogEntry",
    "parse_log_line",
    "parse_file",
    "ThreatDetector",
    "ThreatMatch",
    "SignatureRule",
    "IPEnricher",
    "IPEnrichment",
    "enrich_ips",
    "ForensicReport",
    "build_forensic_report",
    "generate_json_report",
    "generate_html_report",
]