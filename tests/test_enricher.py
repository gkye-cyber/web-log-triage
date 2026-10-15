from pathlib import Path
import sys
import unittest
# adding src directory to sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from web_log_triage.enricher import IPEnricher, enrich_ips
from tests.test_detector import make_entry

class TestEnricher(unittest.TestCase):
    # initializing offline testing
    def setUp(self):
        self.enricher = IPEnricher(enable_geoip=False)

    # classify locally without network requests
    def test_private_ip_classification(self):
        result1 = self.enricher.enrich("192.168.1.10")
        result2 = self.enricher.enrich("10.0.0.1")
        self.assertTrue(result1.is_private)
        self.assertEqual(result1.country, "Internal/Private")
        self.assertEqual(result1.city, "Local Network")
        self.assertTrue(result2.is_private)

    # verify local host is marked private
    def test_loopback_ip_classification(self):
        result = self.enricher.enrich("127.0.0.1")
        self.assertTrue(result.is_private)
        self.assertEqual(result.country, "Internal/Private")

    # verify malformed ip handling
    def test_malformed_ip_handling(self):
        result1 = self.enricher.enrich("not_an_ip")
        result2 = self.enricher.enrich("999.999.999.999")
        self.assertIn("Malformed IP", result1.threat_labels)
        self.assertIn("Malformed IP", result2.threat_labels)

    # verify cache behavior
    def test_cache_behavior(self):
        ip = "192.168.1.50"
        result1 = self.enricher.enrich(ip)
        result2 = self.enricher.enrich(ip)
        self.assertIn(ip, self.enricher.cache)
        self.assertIs(result1, result2) # checkexact chached object in memory

    # verify public ip offline fallback
    def test_offline_public_ip_fallback(self):
        result = self.enricher.enrich("8.8.8.8")
        self.assertFalse(result.is_private)
        self.assertEqual(result.country, "Unknown")
        self.assertEqual(result.country_code, "-")

    # verify batch ips
    def test_enrich_ips_batch(self):
        entries = [
            make_entry(ip="192.168.1.10"),
            make_entry(ip="192.168.1.10"), # duplicate ip to test deduplication
            make_entry(ip="10.0.0.1")
        ]
        results = enrich_ips(entries, enricher=self.enricher)

        # should result in 2 unique IP enrichments
        self.assertEqual(len(results), 2)
        self.assertIn("192.168.1.10", results)
        self.assertIn("10.0.0.1", results)
        self.assertTrue(results["192.168.1.10"].is_private)