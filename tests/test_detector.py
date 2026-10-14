import sys
import unittest
from pathlib import Path
# adding src directory to sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from web_log_triage.parser import LogEntry
from web_log_triage.detector import check_signatures, detect_brute_force, ThreatDetector


### helper function to create a LogEntry for testing
def make_entry(
        ip="192.168.1.1",
        method="GET",
        uri="/",
        status_code=200,
        user_agent="Mozilla/5.0",
        referrer="-"
) -> LogEntry:
    return LogEntry(
        ip=ip,
        timestamp=None,
        method=method,
        raw_uri=uri,
        decoded_uri=uri,
        protocol="HTTP/1.1",
        status_code=status_code,
        response_size=100,
        referrer=referrer,
        user_agent=user_agent,
        raw_line=""
    )

### signature and brute force detection tests
class TestDetector(unittest.TestCase):
    def test_benign_traffic(self):
        entry = make_entry(uri="/index.html", user_agent="Mozilla/5.0")
        matches = check_signatures(entry)
        self.assertEqual(len(matches), 0)  # no matches expected

    def test_sql_injection(self):
        entry = make_entry(uri="/products.php?id=1 UNION SELECT null, password FROM users")
        matches = check_signatures(entry)
        self.assertEqual(matches[0].mitre_id, "T1190")  # SQL Injection MITRE ID

    def test_lfi_detection(self):
        entry = make_entry(uri="/static/../../../../etc/passwd")
        matches = check_signatures(entry)
        self.assertTrue(any(m.category == "LFI" for m in matches))  # LFI category should be detected

    def test_rce_detection(self):
        entry = make_entry(uri="/cgi-bin/test.sh?cmd=whoami;id")
        matches = check_signatures(entry)
        self.assertTrue(any(m.category == "RCE" for m in matches)) # RCE category should be detected
        self.assertEqual(matches[0].mitre_tactic, "Execution")  # MITRE tactic for RCE

    def test_scanner_user_agent_detection(self):
        entry = make_entry(user_agent="sqlmap/1.6.0")
        matches = check_signatures(entry)
        self.assertTrue(any(m.category == "Scanner" for m in matches))  # Scanner category should be detected
        self.assertEqual(matches[0].mitre_tactic, "Reconnaissance")  # MITRE tactic for scanners

    def test_brute_force_below_threshold(self):
        entries = [make_entry(ip="10.0.0.1", status_code=404) for _ in range(2)] # generates a list of 2 entries
        matches = detect_brute_force(entries, threshold=3)
        self.assertEqual(len(matches), 0) # no matches expected

    def test_brute_force_at_or_above_threshold(self):
        entries = [make_entry(ip="10.0.0.1", status_code=404) for _ in range(3)] # generates a list of 3 entries
        matches = detect_brute_force(entries, threshold=3)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].category, "Brute Force")
        self.assertEqual(matches[0].entry.ip, "10.0.0.1")

    # end-to-end test
    def test_threat_detector_end_to_end(self):
        entries = [
          make_entry(uri="/index.html", user_agent="Mozilla/5.0"), # benign
          make_entry(uri="/products.php?id=1 UNION SELECT null, password FROM users"), # sqli
          make_entry(ip="10.0.0.1", status_code=404, uri="/admin"),
          make_entry(ip="10.0.0.1", status_code=404, uri="/login"),
          make_entry(ip="10.0.0.1", status_code=404, uri="/.env") # brute force attempts
        ]
        detector = ThreatDetector()
        matches = detector.analyze(entries) 
        self.assertGreater(len(matches), 0)