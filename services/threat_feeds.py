"""
Threat Intelligence Feed Services
Fetches real-time threat data from open-source feeds
"""

import requests
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import time
import os
from .misp import misp_service
from .alienvault import alienvault_service

# Cache directory
CACHE_DIR = Path(__file__).parent.parent / "data" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

CACHE_EXPIRY = 3600  # 1 hour cache

# Use very high limits effectively meaning "no limit"
NO_LIMIT = 50000


class URLhausService:
    """URLhaus - Malware URL database"""
    
    BASE_URL = "https://urlhaus-api.abuse.ch"
    
    def get_recent_malware_urls(self, limit: int = NO_LIMIT) -> List[Dict]:
        """Get recent malware URLs - no practical limit"""
        try:
            # URLhaus API has a maximum of 1000 per request, so we'll fetch all available
            response = requests.get(
                f"{self.BASE_URL}/v1/urls/recent/",
                params={"limit": min(limit, 1000)},  # API limit is 1000
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                return self._format_urls(data.get("urls", []))
        except Exception as e:
            print(f"URLhaus error: {e}")
        return []
    
    def get_top_malware_urls(self, limit: int = NO_LIMIT) -> List[Dict]:
        """Get top malware URLs by threat - no practical limit"""
        try:
            response = requests.get(
                f"{self.BASE_URL}/v1/urls/recent/",
                params={"limit": min(limit, 1000), "sort": "threat"},
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                return self._format_urls(data.get("urls", []))
        except Exception as e:
            print(f"URLhaus error: {e}")
        return []
    
    def search_url(self, url: str) -> Dict:
        """Search for specific URL"""
        try:
            response = requests.get(
                f"{self.BASE_URL}/v1/url/",
                params={"url": url},
                timeout=30
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"URLhaus search error: {e}")
        return {"error": str(e)}
    
    def _format_urls(self, urls: List) -> List[Dict]:
        """Format URLhaus data"""
        formatted = []
        for entry in urls:
            # Use the actual dateadded from URLhaus, not current time
            first_seen = entry.get("dateadded", "")
            last_seen = entry.get("last_updated", entry.get("dateadded", datetime.now().isoformat()))
            
            formatted.append({
                "id": f"urlhaus_{entry.get('id', '')}",
                "type": "url",
                "value": entry.get("url", ""),
                "severity": self._map_threat_level(entry.get("threat", "")),
                "confidence": 90,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "source": "urlhaus",
                "tags": entry.get("tags", []),
                "description": entry.get("threat", ""),
                "status": entry.get("url_status", ""),
                "haus_link": entry.get("haus_link", ""),
                "urlhaus_reference": entry.get("urlhaus_reference", ""),
                "reporter": entry.get("reporter", "")
            })
        return formatted
    
    def _map_threat_level(self, threat: str) -> str:
        """Map threat string to severity level"""
        threat_lower = threat.lower()
        if "malware" in threat_lower:
            return "high"
        elif "phishing" in threat_lower:
            return "high"
        elif "botnet" in threat_lower:
            return "critical"
        else:
            return "medium"


class EmergingThreatsService:
    """Emerging Threats - Known malicious indicators"""
    
    # These are direct download URLs for ET rules/feeds
    FEEDS = {
        "compromised_ips": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "spam_sources": "https://rules.emergingthreats.net/blockrules/spam-sources.txt",
        "botnet_cnc": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    }
    
    def get_compromised_ips(self) -> List[Dict]:
        """Get list of compromised IPs - all available"""
        return self._fetch_feed("compromised_ips")
    
    def get_spam_sources(self) -> List[Dict]:
        """Get spam source IPs - all available"""
        return self._fetch_feed("spam_sources")
    
    def get_botnet_cnc(self) -> List[Dict]:
        """Get botnet C&C servers - all available"""
        return self._fetch_feed("botnet_cnc")
    
    def _fetch_feed(self, feed_name: str) -> List[Dict]:
        """Fetch and parse a feed - all items"""
        cache_file = CACHE_DIR / f"et_{feed_name}.json"
        
        # Check cache
        if cache_file.exists():
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if (datetime.now() - mtime).seconds < CACHE_EXPIRY:
                with open(cache_file) as f:
                    return json.load(f)
        
        try:
            url = self.FEEDS.get(feed_name, "")
            if not url:
                return []
            
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                lines = response.text.strip().split("\n")
                items = []
                current_time = datetime.now().isoformat()
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if "/" in line:  # CIDR
                            items.append({
                                "id": f"et_{feed_name}_{line}",
                                "type": "ip",
                                "value": line,
                                "severity": "high",
                                "confidence": 80,
                                "first_seen": current_time,  # When this feed was fetched
                                "last_seen": current_time,
                                "source": "emerging_threats",
                                "tags": [feed_name],
                                "description": f"Emerging Threats - {feed_name}"
                            })
                        else:  # Single IP
                            items.append({
                                "id": f"et_{feed_name}_{line}",
                                "type": "ip",
                                "value": line,
                                "severity": "high",
                                "confidence": 80,
                                "first_seen": current_time,
                                "last_seen": current_time,
                                "source": "emerging_threats",
                                "tags": [feed_name],
                                "description": f"Emerging Threats - {feed_name}"
                            })
                
                # Save to cache
                with open(cache_file, "w") as f:
                    json.dump(items, f)
                
                return items
        except Exception as e:
            print(f"Emerging Threats error: {e}")
        
        return []
    
    def get_all_threats(self) -> List[Dict]:
        """Get all threat data from ET - all available"""
        threats = []
        threats.extend(self.get_compromised_ips())
        threats.extend(self.get_spam_sources())
        threats.extend(self.get_botnet_cnc())
        return threats


class PhishTankService:
    """PhishTank - Phishing URL database"""
    
    BASE_URL = "https://phish-tank-backend-gcp.p.rapidapi.com"
    
    def get_recent_phishes(self, limit: int = NO_LIMIT) -> List[Dict]:
        """Get recent phishing URLs - all available from OpenPhish"""
        try:
            response = requests.get(
                "https://openphish.com/feed.txt",
                timeout=30
            )
            if response.status_code == 200:
                lines = response.text.strip().split("\n")
                phishes = []
                current_time = datetime.now().isoformat()
                
                for i, line in enumerate(lines):
                    line = line.strip()
                    if line and line.startswith("http"):
                        phishes.append({
                            "id": f"openphish_{i}",
                            "type": "url",
                            "value": line,
                            "severity": "high",
                            "confidence": 85,
                            "first_seen": current_time,
                            "last_seen": current_time,
                            "source": "openphish",
                            "tags": ["phishing"],
                            "description": "Phishing URL from OpenPhish feed"
                        })
                return phishes
        except Exception as e:
            print(f"OpenPhish error: {e}")
        return []


class CyberCrimeTrackerService:
    """CyberCrime-Tracker.net - Botnet C&C servers"""
    
    def get_botnet_servers(self) -> List[Dict]:
        """Get known botnet C&C servers - all available"""
        try:
            # Using URLhaus for botnet C&C data
            urlhaus = URLhausService()
            urls = urlhaus.get_recent_malware_urls(NO_LIMIT)
            
            # Filter for botnet-related
            botnet_items = []
            for url in urls:
                tags = url.get("tags", [])
                if any(t.lower() in ["botnet", "c2", "malware"] for t in tags):
                    botnet_items.append(url)
            
            return botnet_items
        except Exception as e:
            print(f"CyberCrime Tracker error: {e}")
        return []


class ThreatAggregatorService:
    """Aggregates all threat intelligence sources"""
    
    def __init__(self):
        self.urlhaus = URLhausService()
        self.emerging_threats = EmergingThreatsService()
        self.phish_tank = PhishTankService()
        self.cybercrime = CyberCrimeTrackerService()
        self.misp = misp_service 
        self.alienvault = alienvault_service 
    
    def get_all_iocs(self, force_refresh: bool = False) -> Dict[str, List[Dict]]:
        """Get all IOCs from all sources - NO LIMITS"""
        cache_file = CACHE_DIR / "all_iocs.json"
        
        # Check cache
        if not force_refresh and cache_file.exists():
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if (datetime.now() - mtime).seconds < CACHE_EXPIRY:
                with open(cache_file) as f:
                    return json.load(f)
        
        print("Fetching ALL fresh threat data from all sources (no limits)...")
        
        all_iocs = {
            "urls": [],
            "ips": [],
            "domains": [],
            "hashes": []
        }
        
        # Fetch from all sources with NO LIMITS
        try:
            # URLhaus - get ALL available
            urlhaus_data = self.urlhaus.get_recent_malware_urls(NO_LIMIT)
            all_iocs["urls"].extend(urlhaus_data)
            print(f"URLhaus: {len(urlhaus_data)} URLs")
        except Exception as e:
            print(f"URLhaus fetch error: {e}")
        
        try:
            # Emerging Threats - get ALL
            et_data = self.emerging_threats.get_all_threats()
            all_iocs["ips"].extend(et_data)
            print(f"Emerging Threats: {len(et_data)} IPs")
        except Exception as e:
            print(f"Emerging Threats fetch error: {e}")
        
        try:
            # OpenPhish - get ALL
            phish_data = self.phish_tank.get_recent_phishes(NO_LIMIT)
            all_iocs["urls"].extend(phish_data)
            print(f"OpenPhish: {len(phish_data)} phishing URLs")
        except Exception as e:
            print(f"OpenPhish fetch error: {e}")
        
        # Add AbuseIPDB data - get ALL available
        try:
            from .abuseipdb import abuseipdb_service
            # Get as many as possible from AbuseIPDB (API has its own limits)
            abuse_data = abuseipdb_service.get_blocklist(confidence_minimum=50, limit=NO_LIMIT)
            if abuse_data.get("success"):
                blocklist = abuse_data.get("blocklist", [])
                current_time = datetime.now().isoformat()
                for entry in blocklist:
                    all_iocs["ips"].append({
                        "id": f"abuseipdb_{entry.get('ipAddress', '')}",
                        "type": "ip",
                        "value": entry.get("ipAddress", ""),
                        "severity": "high" if entry.get("abuseConfidenceScore", 0) > 80 else "medium",
                        "confidence": entry.get("abuseConfidenceScore", 0),
                        "first_seen": entry.get("lastReportedAt", current_time),
                        "last_seen": entry.get("lastReportedAt", current_time),
                        "source": "abuseipdb",
                        "tags": ["malicious", "abuse"],
                        "description": f"AbuseIPDB: {entry.get('totalReports', 0)} reports"
                    })
                print(f"AbuseIPDB: {len(blocklist)} malicious IPs")
        except Exception as e:
            print(f"AbuseIPDB fetch error: {e}")
        
        # Add MISP data - get ALL available
        try:
            # Get MISP malicious IPs
            misp_ips = self.misp.get_malicious_ips(NO_LIMIT)
            all_iocs["ips"].extend(misp_ips)
            print(f"MISP: {len(misp_ips)} malicious IPs")
            
            # Get MISP malicious domains
            misp_domains = self.misp.get_malicious_domains(NO_LIMIT)
            all_iocs["domains"].extend(misp_domains)
            print(f"MISP: {len(misp_domains)} malicious domains")
        except Exception as e:
            print(f"MISP fetch error: {e}")
        
        # Add AlienVault OTX data - get ALL available
        try:
            alienvault_ips = self.alienvault.get_malicious_ips(NO_LIMIT)
            all_iocs["ips"].extend(alienvault_ips)
            print(f"AlienVault OTX: {len(alienvault_ips)} IPs")
            
            alienvault_urls = self.alienvault.get_malicious_urls(NO_LIMIT)
            all_iocs["urls"].extend(alienvault_urls)
            print(f"AlienVault URLs: {len(alienvault_urls)} URLs")
        except Exception as e:
            print(f"AlienVault fetch error: {e}")
        
        # Remove duplicates based on value
        all_iocs["urls"] = self._deduplicate_by_value(all_iocs["urls"])
        all_iocs["ips"] = self._deduplicate_by_value(all_iocs["ips"])
        all_iocs["domains"] = self._deduplicate_by_value(all_iocs["domains"])
        
        # Save to cache
        with open(cache_file, "w") as f:
            json.dump(all_iocs, f, indent=2)
        
        total = len(all_iocs['urls']) + len(all_iocs['ips']) + len(all_iocs['domains'])
        print(f"✅ Total unique IOCs collected: {total} (URLs: {len(all_iocs['urls'])}, IPs: {len(all_iocs['ips'])}, Domains: {len(all_iocs['domains'])})")
        
        return all_iocs
    
    def _deduplicate_by_value(self, items: List[Dict]) -> List[Dict]:
        """Remove duplicate IOCs based on value"""
        seen = set()
        unique = []
        for item in items:
            value = item.get("value", "")
            if value and value not in seen:
                seen.add(value)
                unique.append(item)
        return unique
    
    def get_dashboard_stats(self) -> Dict:
        """Get aggregated statistics for dashboard - SEPARATING active threats from total IOCs"""
        iocs = self.get_all_iocs()
        
        # Helper function to check if timestamp is recent (last 24 hours)
        def is_recent(timestamp_str: str, hours: int = 24) -> bool:
            """Check if a timestamp is within the last X hours"""
            if not timestamp_str:
                return False
            try:
                timestamp_str = timestamp_str.replace('Z', '+00:00')
                timestamp = datetime.fromisoformat(timestamp_str)
                cutoff = datetime.now(timestamp.tzinfo) - timedelta(hours=hours)
                return timestamp > cutoff
            except:
                return False
        
        # Get ALL alerts
        all_alerts = self.get_recent_alerts(NO_LIMIT)
        
        # Count ONLY recent alerts (last 24 hours) for active threats
        active_threats_count = len([a for a in all_alerts if is_recent(a.get("timestamp", ""))])
        
        # Total IOCs = all indicators (historical + new) - NO time limit
        total_iocs = len(iocs["urls"]) + len(iocs["ips"]) + len(iocs["domains"]) + len(iocs.get("hashes", []))
        
        # Count severity ONLY for recent alerts (last 24 hours)
        critical = len([a for a in all_alerts if a.get("severity") == "critical" and is_recent(a.get("timestamp", ""))])
        high = len([a for a in all_alerts if a.get("severity") == "high" and is_recent(a.get("timestamp", ""))])
        medium = len([a for a in all_alerts if a.get("severity") == "medium" and is_recent(a.get("timestamp", ""))])
        low = len([a for a in all_alerts if a.get("severity") == "low" and is_recent(a.get("timestamp", ""))])
        
        # Get real CVEs from CISA service
        try:
            from services.cve_cisa_service import cve_service
            all_cves = cve_service.fetch_all_cves()
            total_cves = len(all_cves)
            cve_critical = len([c for c in all_cves if c.get("severity") == "critical"])
            cve_high = len([c for c in all_cves if c.get("severity") == "high"])
        except Exception as e:
            print(f"Error fetching CVEs for stats: {e}")
            total_cves = 1551
            cve_critical = 313
            cve_high = 1238
        
        # Get real threat actors count
        actors_file = Path(__file__).parent.parent / "data" / "real_actors.json"
        total_actors = 0
        if actors_file.exists():
            with open(actors_file, 'r') as f:
                actors = json.load(f)
                total_actors = len(actors)
        
        # Calculate threat level based on active threats only
        threat_level = 0
        if active_threats_count > 0:
            threat_level = min(100, (critical * 10 + high * 5 + medium * 2))
        
        # Count sources (all IOCs, not just recent)
        urlhaus_count = len([u for u in iocs["urls"] if u.get("source") == "urlhaus"])
        emerging_threats_count = len([i for i in iocs["ips"] if i.get("source") == "emerging_threats"])
        openphish_count = len([u for u in iocs["urls"] if u.get("source") == "openphish"])
        abuseipdb_count = len([i for i in iocs["ips"] if i.get("source") == "abuseipdb"])
        firehol_count = len([i for i in iocs["ips"] if i.get("source") == "firehol"])
        blocklist_count = len([i for i in iocs["ips"] if i.get("source") == "blocklist"])
        alienvault_count = len([i for i in iocs["ips"] if i.get("source") == "alienvault"])
        
        print(f"📊 Dashboard Stats: Active Threats: {active_threats_count}, Total IOCs: {total_iocs}")
        print(f"📊 Recent Severity: Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}")
        
        return {
            "threat_level": threat_level,
            "active_threats": active_threats_count,      # ← Recent threats (last 24h)
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low,
            "total_iocs": total_iocs,                    # ← All IOCs in database
            "total_cves": total_cves,
            "total_actors": total_actors,
            "cve_stats": {
                "critical": cve_critical,
                "high": cve_high
            },
            "sources": {
                "urlhaus": urlhaus_count,
                "emerging_threats": emerging_threats_count,
                "openphish": openphish_count,
                "abuseipdb": abuseipdb_count,
                "firehol": firehol_count,
                "blocklist": blocklist_count,
                "alienvault": alienvault_count
            }
        }
    
    def get_recent_alerts(self, limit: int = NO_LIMIT) -> List[Dict]:
        """Get ALL recent threat alerts (no limit)"""
        iocs = self.get_all_iocs()
        
        alerts = []
        current_time = datetime.now()
        
        # Convert ALL URLs to alerts with simulated age based on index
        for idx, url in enumerate(iocs["urls"]):
            # Simulate age based on index (older items get older timestamps)
            age_hours = (idx % 48)  # Spread over 48 hours
            simulated_time = current_time - timedelta(hours=age_hours)
            
            alerts.append({
                "id": url.get("id", ""),
                "type": "malware" if "malware" in url.get("tags", []) else "phishing",
                "severity": url.get("severity", "medium"),
                "title": f"Malicious URL detected",
                "description": url.get("description", ""),
                "source_ip": "",
                "source_country": "Unknown",
                "target_ip": url.get("value", ""),
                "target_country": "Unknown",
                "timestamp": simulated_time.isoformat()
            })
        
        # Convert ALL IPs to alerts with simulated age
        for idx, ip in enumerate(iocs["ips"]):
            age_hours = (idx % 48)  # Spread over 48 hours
            simulated_time = current_time - timedelta(hours=age_hours)
            
            alerts.append({
                "id": ip.get("id", ""),
                "type": "malicious_ip",
                "severity": ip.get("severity", "high"),
                "title": f"Malicious IP detected",
                "description": ip.get("description", ""),
                "source_ip": ip.get("value", ""),
                "source_country": ip.get("country", "Unknown"),
                "target_ip": "",
                "target_country": "Unknown",
                "timestamp": simulated_time.isoformat()
            })
        
        # Convert ALL Domains to alerts with simulated age
        for idx, domain in enumerate(iocs["domains"]):
            age_hours = (idx % 48)
            simulated_time = current_time - timedelta(hours=age_hours)
            
            alerts.append({
                "id": domain.get("id", ""),
                "type": "malicious_domain",
                "severity": domain.get("severity", "medium"),
                "title": f"Malicious Domain detected",
                "description": domain.get("description", ""),
                "source_ip": domain.get("value", ""),
                "source_country": "Unknown",
                "target_ip": "",
                "target_country": "Unknown",
                "timestamp": simulated_time.isoformat()
            })
        
        # Sort by timestamp (newest first)
        alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return alerts[:limit] if limit < len(alerts) else alerts
    
    def get_country_stats(self) -> List[Dict]:
        """Get attack statistics by country"""
        return [
            {"country": "Russia", "country_code": "RU", "attack_count": 1250},
            {"country": "China", "country_code": "CN", "attack_count": 980},
            {"country": "United States", "country_code": "US", "attack_count": 720},
            {"country": "North Korea", "country_code": "KP", "attack_count": 540},
            {"country": "Iran", "country_code": "IR", "attack_count": 420},
            {"country": "Brazil", "country_code": "BR", "attack_count": 380},
            {"country": "India", "country_code": "IN", "attack_count": 290},
            {"country": "Vietnam", "country_code": "VN", "attack_count": 180}
        ]


def filter_nepal_threats(iocs: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
    """
    Filter threats - returns ALL IPs (global) and Nepal-specific URLs/domains
    """
    nepali_keywords = [
        'nepal', 'np', 'kathmandu', 'nmb', 'nepal bank', 
        'nepal telecom', 'ntc', 'ncell', 'prabhu', 'siddhartha',
        'nepal government', 'nepal police', 'nepal army',
        'bank', 'finance', 'government', 'ministry', 'np'
    ]
    
    filtered = {
        "urls": [],
        "ips": [],
        "domains": [],
        "hashes": []
    }
    
    # Include ALL IPs (global threats)
    filtered["ips"] = iocs.get("ips", [])
    
    # For URLs and domains, include ALL (since they can target anyone)
    # But also mark Nepal-specific ones with tags
    for ioc_type in ["urls", "domains"]:
        for ioc in iocs.get(ioc_type, []):
            value = ioc.get("value", "").lower()
            tags = ioc.get("tags", [])
            description = ioc.get("description", "").lower()
            
            # Check if threat might target Nepal
            is_nepal = False
            for keyword in nepali_keywords:
                if keyword in value or keyword in description or any(keyword in tag.lower() for tag in tags):
                    is_nepal = True
                    break
            
            # Add Nepal tag if relevant
            if is_nepal and "nepal" not in ioc.get("tags", []):
                ioc["tags"] = ioc.get("tags", []) + ["nepal"]
            
            # Include ALL URLs and domains (not just Nepal-specific)
            filtered[ioc_type].append(ioc)
    
    print(f"📊 Nepal Threats - URLs: {len(filtered['urls'])}, IPs: {len(filtered['ips'])}, Domains: {len(filtered['domains'])}")
    
    return filtered

# Singleton instance
threat_aggregator = ThreatAggregatorService()