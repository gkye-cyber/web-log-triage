from dataclasses import dataclass, field
from typing import Iterable, Optional
from web_core_trace.parser import LogEntry
import ipaddress
import json
import urllib.request
import urllib.error

@dataclass
class IPEnrichment:
    ip: str
    country: str = "Unknown"
    country_code: str = "-"
    city: str = "Unknown"
    org: str = "Unknown"
    is_private: bool = False
    is_threat: bool = False
    threat_labels: list[str] = field(default_factory=list)

class IPEnricher:
    def __init__(self, enable_geoip: bool = True, timeout: int = 2):
        self.cache: dict[str, IPEnrichment] = {}
        self.enable_geoip = enable_geoip
        self.timeout = timeout

    ## helper method
    def _classify_special_ip(self, ip_str: str) -> Optional[IPEnrichment]:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
             return IPEnrichment(ip=ip_str, threat_labels=["Malformed IP"])
        # handles private addresses
        if addr.is_private or addr.is_loopback:
            return IPEnrichment(
                ip=ip_str, 
                country="Internal/Private", 
                city="Local Network", 
                org="Private Network",
                is_private=True
                )
        # handles documented test networks
        if not addr.is_global:
            return IPEnrichment(
                ip=ip_str,
                country="Documentation/TestNet",
                city="RFC 5737",
                org="Reserved Testnet",
                is_private=True,
                threat_labels=["Test Network"]
            )
        return None


    ## geolocation lookup method
    def _lookup_geoip(self, ip_str: str) -> tuple[str, str, str, str]: # tuple for fetching geographical strings
        # returns defaults without making network calls
        if not self.enable_geoip:
                    return ("Unknown", "-", "Unknown", "Unknown")
        url = f"http://ip-api.com/json/{ip_str}?fields=status,country,countryCode,city,isp,org"
        try:
             req = urllib.request.Request(url, headers={"User-Agent":"web-log-triage/1.0"})
             with urllib.request.urlopen(req, timeout=self.timeout) as response:
                  data = json.loads(response.read().decode("utf-8"))
                  if data.get("status") == "success":
                       country = data.get("country", "Unknown")
                       country_code = data.get("countryCode", "-")
                       city = data.get("city", "Unknown")
                       org = data.get("isp") or data.get("org") or "Unknown"
                       return (country, country_code, city, org)
        except Exception:
             # gracefull fallback
             pass
        return ("Unknown", "-", "Unknown", "Unknown")

    ### main enricher method
    def enrich(self, ip: str) -> IPEnrichment:
         """Enriches IP address with network type and geolocation
         using cache"""
         if ip in self.cache:
              return self.cache[ip]

         # check if private, loopback, or testnet
         special = self._classify_special_ip(ip)
         if special is not None:
              self.cache[ip] = special
              return special

         # for public IPs, perform geolocation lookup
         country, country_code, city, org = self._lookup_geoip(ip)

         # construct result, store in cache, and return
         enrichment = IPEnrichment(
              ip=ip,
              country=country,
              country_code=country_code,
              city=city,
              org=org,
              is_private=False,
              is_threat=False
         )
         self.cache[ip] = enrichment
         return enrichment

### standalone batch helper
def enrich_ips(entries: Iterable[LogEntry], enricher: Optional[IPEnricher] = None) -> dict[str, IPEnrichment]:
     # Enriches all unique IPs across an iterable of LogEntry objects
     enricher = enricher or IPEnricher()
     unique_ips = {entry.ip for entry in entries}
     return {ip: enricher.enrich(ip) for ip in unique_ips}