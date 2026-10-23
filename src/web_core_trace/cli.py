import argparse
import sys
from pathlib import Path
from typing import Optional
from web_core_trace.parser import parse_file
from web_core_trace.detector import ThreatDetector
from web_core_trace.enricher import IPEnricher, enrich_ips
from web_core_trace.reporter import (
    build_forensic_report,
    generate_json_report,
    generate_html_report,
    ForensicReport
)

### args
def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Web Log Triage",
        description="Automated Web Server Access Log Threat Hunter & Forensic Triage Tool"
    )
    parser.add_argument("-f", "--format", choices=["console", "html", "json"], default="console", help="Report format: console, html, or json (default: console)")
    parser.add_argument("-o", "--output", type=str, help="Output file path for html/json")
    parser.add_argument("log_file", type=str, help="Path to the access log file (Combined/Common format)")
    parser.add_argument("--threshold", type=int, default=3, help="Brute-force 404/403 threshold (default: 3)")
    parser.add_argument("--no-geoip", action="store_true", help="Disable online GeoIP lookups (offline mode)")
    return parser.parse_args(args)

### prints clean ASCII SOC triage summary
def _print_console_summary(report: ForensicReport) -> None:
    print("\n" + "=" * 65)
    print(" WEB LOG TRIAGE - FORENSIC SUMMARY")
    print("=" * 65)
    print(f" Total Requests Analyzed : {report.total_requests}")
    print(f" Unique IP Addresses     : {report.unique_ips}")
    print(f" Total Threats Detected  : {report.total_threats}")
    print("=" * 65)

    print("\n[+] Top Offending IPs & Network Geolocation:")
    if report.top_attacking_ips:
        for ip, count in report.top_attacking_ips:
            enrichment = report.ip_enrichments.get(ip)
            geo = f"{enrichment.country} ({enrichment.city})" if enrichment else "Unknown"
            print(f"  {ip:<16} : {count:>2} alerts | Location: {geo}")
    else:
        print("  None detected (Clean traffic)")

    print("\n[+] Threat Categories Breakdown:")
    for cat, count in report.category_distribution.items():
        print(f" {cat:<22} : {count}")

    print("\n[+] Detailed Threat Findings:")
    if report.threats:
        for i, t in enumerate(report.threats, 1):
            ts = t.entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if t.entry.timestamp else "-"
            print(f"  [{i:>2}] [{t.severity:<8}] {t.category:<12} (MITRE {t.mitre_id or '-'}) from {t.entry.ip}")
            print(f"     Payload : {t.matched_payload[:55]}")
            print(f"     URI     : {t.entry.decoded_uri[:65]}")
    else:
        print("  Clean traffic. No security alerts identified.")
    print("=" * 65 + "\n")

### main pipline
# verify if logs exists
def main_pipeline():
    args = parse_args()
    log_path = Path(args.log_file)
    if not log_path.is_file():
        print(f"[-] Error: File not found: {args.log_file}", file=sys.stderr)
        return 1

    # run pipeline
    entries = list(parse_file(log_path))
    if not entries:
        print("[-] Warning: No valid log entries found to parse.", file=sys.stderr)
        return 0

    # threat detection
    detector = ThreatDetector(brute_force_threshold=args.threshold)
    threats = detector.analyze(entries)

    # IP Enrichment
    enricher = IPEnricher(enable_geoip=not args.no_geoip)
    enrichments = enrich_ips(entries, enricher)

    # Metrics & Reporting
    report = build_forensic_report(entries, threats, enrichments)

    ### output handling
    if args.format == "json":
        json_output = generate_json_report(report, args.output)
        if args.output:
            print(f"[+] Forensic JSON report saved to: {args.output}")
        else:
            print(json_output)

    elif args.format == "html":
        out_file = args.output or "forensic_report.html"
        generate_html_report(report, out_file)
        print(f"[+] Forensic HTML dashboard generated: {out_file}")

    else: # default to console
        _print_console_summary(report)

    return 0

if __name__ == "__main__":
    sys.exit(main_pipeline())