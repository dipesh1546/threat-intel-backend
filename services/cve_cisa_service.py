"""
CISA KEV Service - Fetches real, actively exploited vulnerabilities from CISA
"""

import json
import requests
import re
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from pathlib import Path
from functools import wraps
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def rate_limit(seconds: float):
    """Rate limiting decorator for API calls"""
    def decorator(func):
        last_called = [0.0]
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            if elapsed < seconds:
                time.sleep(seconds - elapsed)
            result = func(*args, **kwargs)
            last_called[0] = time.time()
            return result
        return wrapper
    return decorator

class CISACVEService:
    """Service for fetching real CVE data from CISA Known Exploited Vulnerabilities catalog"""

    def __init__(self):
        self.cache_file = Path(__file__).parent.parent / "data" / "cve_cisa_cache.json"
        self.basic_cache_file = Path(__file__).parent.parent / "data" / "cve_basic_cache.json"
        self.cache_duration = 3600  # 1 hour cache
        self.basic_cache_duration = 300  # 5 minutes for basic cache (faster refresh)
        self.cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _map_to_cwe(self, description: str, product: str, vendor: str) -> str:
        """Map vulnerability description to CWE based on keywords"""
        text = (description + " " + product + " " + vendor).lower()
        
        # CWE mapping dictionary - ordered by specificity
        cwe_mapping = [
            (['sql', 'injection', 'database', 'query'], 'CWE-89'),
            (['xss', 'cross-site', 'cross site', 'scripting'], 'CWE-79'),
            (['command', 'injection', 'os command', 'code injection', 'remote code'], 'CWE-78'),
            (['buffer', 'overflow', 'memory', 'corruption', 'heap', 'stack'], 'CWE-119'),
            (['authentication', 'bypass', 'auth bypass', 'credential', 'login'], 'CWE-287'),
            (['path', 'traversal', 'directory', 'file', 'folder'], 'CWE-22'),
            (['input', 'validation', 'sanitize', 'filter', 'sanitization'], 'CWE-20'),
            (['csrf', 'request forgery', 'cross-site request'], 'CWE-352'),
            (['information', 'exposure', 'disclosure', 'leak', 'reveal'], 'CWE-200'),
            (['upload', 'file upload', 'unrestricted upload'], 'CWE-434'),
            (['privilege', 'escalation', 'privilege escalation', 'elevation'], 'CWE-269'),
            (['denial', 'dos', 'service', 'crash', 'resource'], 'CWE-400'),
            (['rce', 'remote code', 'code execution', 'arbitrary code'], 'CWE-94'),
            (['ssrf', 'server-side request', 'request forgery'], 'CWE-918'),
            (['xxe', 'xml external', 'external entity'], 'CWE-611'),
            (['deserialization', 'unserialize', 'serialization'], 'CWE-502'),
            (['clickjacking', 'ui redress', 'frame'], 'CWE-1021'),
            (['race', 'race condition', 'time-of-check', 'toctou'], 'CWE-362'),
            (['cryptography', 'encryption', 'weak crypto', 'ssl', 'tls'], 'CWE-326'),
            (['hard-coded', 'hardcoded', 'default credential'], 'CWE-798'),
            (['url redirection', 'open redirect'], 'CWE-601'),
            (['null pointer', 'null dereference'], 'CWE-476'),
            (['use after free', 'use-after-free'], 'CWE-416'),
            (['format string'], 'CWE-134'),
            (['integer overflow', 'integer underflow'], 'CWE-190'),
        ]
        
        for keywords, cwe in cwe_mapping:
            if any(k in text for k in keywords):
                return cwe
        
        # Check for CWE in the text directly
        cwe_pattern = r'CWE[-\s]*(\d+)'
        match = re.search(cwe_pattern, text, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        
        return "CWE-20"  # Default: Improper Input Validation

    def fetch_all_cves(self) -> List[Dict]:
        """Fetch ALL real CVEs from CISA KEV feed with CWE mapping"""
        logger.info("=== Fetching ALL CVEs from CISA KEV ===")

        try:
            # Check cache
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                    ts = datetime.fromisoformat(cache.get("timestamp", "2000-01-01"))
                    if (datetime.now() - ts).seconds < self.cache_duration:
                        cached_cves = cache.get("cves", [])
                        logger.info(f"✅ Using cached data: {len(cached_cves)} CVEs")
                        return cached_cves

            logger.info("📡 Fetching ALL CVEs from CISA KEV feed...")
            response = requests.get(self.cisa_url, timeout=15)

            if response.status_code != 200:
                logger.error(f"❌ API error: {response.status_code}")
                return self._fetch_basic_from_nvd()

            data = response.json()
            total = data.get('count', 0)
            logger.info(f"📡 Total CISA KEV CVEs available: {total}")

            all_cves = []
            cwe_counter = defaultdict(int)
            
            for vuln in data.get("vulnerabilities", []):
                try:
                    cve_id = vuln.get("cveID", "")
                    if not cve_id:
                        continue

                    # Determine severity based on ransomware use
                    cvss_score = 8.5
                    severity = "high"
                    
                    if vuln.get("knownRansomwareCampaignUse") == "Known":
                        cvss_score = 9.5
                        severity = "critical"

                    # Get description
                    description = vuln.get("shortDescription", "")
                    if not description:
                        description = f"Actively exploited vulnerability in {vuln.get('vendorProject', '')} {vuln.get('product', '')}"

                    # Get product and vendor for CWE mapping
                    product = vuln.get("product", "")
                    vendor = vuln.get("vendorProject", "")
                    
                    # Map to CWE based on description
                    cwe = self._map_to_cwe(description, product, vendor)
                    cwe_counter[cwe] += 1

                    # Get affected software
                    affected_software = []
                    if vendor and product:
                        affected_software.append(f"{vendor} {product}")
                    elif product:
                        affected_software.append(product)
                    
                    if not affected_software:
                        affected_software = ["Various"]

                    # Get references
                    references = []
                    if vuln.get("notes"):
                        urls = re.findall(r'https?://[^\s]+', vuln.get("notes", ""))
                        references.extend(urls[:2])
                    
                    if not references:
                        references = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]

                    all_cves.append({
                        "id": cve_id,
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "description": description,
                        "published": vuln.get("dateAdded", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "affected_software": list(set(affected_software))[:3],
                        "references": list(set(references))[:3],
                        "source": "CISA KEV",
                        "ransomware_campaign": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                        "cwe": cwe,
                        "required_action": vuln.get("requiredAction", "")
                    })

                except Exception as e:
                    logger.error(f"Error parsing {cve_id if 'cve_id' in locals() else 'unknown'}: {e}")
                    continue

            logger.info(f"✅ Parsed {len(all_cves)} CVEs from CISA KEV")
            logger.info(f"📊 CWE Distribution: {dict(sorted(cwe_counter.items(), key=lambda x: x[1], reverse=True)[:10])}")

            if all_cves:
                cache_data = {
                    "timestamp": datetime.now().isoformat(),
                    "cves": all_cves
                }
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.cache_file, 'w') as f:
                    json.dump(cache_data, f, indent=2)
                logger.info(f"💾 Cached {len(all_cves)} CVEs")
                return all_cves

            return self._fetch_basic_from_nvd()

        except Exception as e:
            logger.error(f"❌ Error fetching CVEs: {e}")
            return self._fetch_basic_from_nvd()

    @rate_limit(1.0)
    def _fetch_nvd_cve_data(self, cve_id: str) -> Optional[Dict]:
        """Fetch additional CVE data from NVD API"""
        try:
            response = requests.get(
                f"{self.nvd_api_url}?cveId={cve_id}",
                timeout=10,
                headers={"User-Agent": "NepalThreatIntel/1.0"}
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if isinstance(vulnerabilities, list) and len(vulnerabilities) > 0:
                    vuln_entry = vulnerabilities[0]
                    if isinstance(vuln_entry, dict):
                        cve_data = vuln_entry.get("cve", {})
                        if cve_data:
                            return self._parse_nvd_cve_data(cve_data)
                    
        except Exception as e:
            logger.error(f"Error fetching NVD data for {cve_id}: {e}")
        
        return None

    def _parse_nvd_cve_data(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse NVD CVE data"""
        try:
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:400]
                    break
            
            cvss_score = 0
            metrics = cve_data.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31 and len(cvss_v31) > 0:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0)
            
            cwe = None
            weaknesses = cve_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe = desc.get("value", "")
                        break
                if cwe:
                    break
            
            return {
                "description": description,
                "cvss_score": float(cvss_score),
                "cwe": cwe,
            }
            
        except Exception as e:
            logger.error(f"Error parsing NVD CVE data: {e}")
            return {}

    def _fetch_basic_from_nvd(self) -> List[Dict]:
        """Fetch basic CVEs from NVD as backup"""
        logger.info("📡 Fetching recent basic CVEs from NVD...")
        
        try:
            params = {
                "resultsPerPage": 100,
                "startIndex": 0
            }
            
            response = requests.get(self.nvd_api_url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                
                for vuln_entry in data.get("vulnerabilities", []):
                    try:
                        if not isinstance(vuln_entry, dict):
                            continue
                        cve_data = vuln_entry.get("cve", {})
                        cve_id = cve_data.get("id", "")
                        if not cve_id:
                            continue
                        
                        description = ""
                        for desc in cve_data.get("descriptions", []):
                            if desc.get("lang") == "en":
                                description = desc.get("value", "")[:400]
                                break
                        
                        cvss_score = 0
                        metrics = cve_data.get("metrics", {})
                        cvss_v31 = metrics.get("cvssMetricV31", [])
                        if cvss_v31 and len(cvss_v31) > 0:
                            cvss_data = cvss_v31[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0)
                        
                        # Determine severity
                        if cvss_score >= 9:
                            severity = "critical"
                        elif cvss_score >= 7:
                            severity = "high"
                        elif cvss_score >= 4:
                            severity = "medium"
                        else:
                            severity = "low"
                        
                        # Try to extract CWE from NVD data
                        cwe = None
                        weaknesses = cve_data.get("weaknesses", [])
                        for weakness in weaknesses:
                            for desc in weakness.get("description", []):
                                if desc.get("lang") == "en":
                                    cwe = desc.get("value", "")
                                    break
                            if cwe:
                                break
                        
                        cves.append({
                            "id": cve_id,
                            "cve_id": cve_id,
                            "cvss_score": float(cvss_score),
                            "severity": severity,
                            "description": description,
                            "published": cve_data.get("published", "").split("T")[0] if cve_data.get("published") else "",
                            "affected_software": ["Various"],
                            "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                            "source": "NVD",
                            "cwe": cwe
                        })
                        
                        if len(cves) >= 100:
                            break
                            
                    except Exception as e:
                        continue
                
                logger.info(f"✅ Fetched {len(cves)} basic CVEs from NVD")
                return cves
                    
        except Exception as e:
            logger.error(f"❌ Error fetching basic CVEs from NVD: {e}")
        
        logger.warning("⚠️ No data available, returning empty list")
        return []


cve_service = CISACVEService()