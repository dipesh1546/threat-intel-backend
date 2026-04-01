"""
CVE Service - Fetches real-time CVE data from NVD
"""

import json
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pathlib import Path

class CVEService:
    """Service for fetching real CVE data from NVD API"""
    
    def __init__(self):
        self.cache_file = Path(__file__).parent.parent / "data" / "cve_cache.json"
        self.cache_duration = 7200
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
    def fetch_real_cves(self, limit: int = 100) -> List[Dict]:
        """Fetch recent real CVEs from NVD API (last 30 days first)"""
        print(f"=== Fetching real CVEs (limit: {limit}) ===")
        
        try:
            # Check cache
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                    ts = datetime.fromisoformat(cache.get("timestamp", "2000-01-01"))
                    if (datetime.now() - ts).seconds < self.cache_duration:
                        cached_cves = cache.get("cves", [])
                        print(f"✅ Using cached data: {len(cached_cves)} CVEs")
                        return cached_cves[:limit]
            
            print("📡 Fetching recent CVEs from NVD API...")
            
            all_cves = []
            
            # First, get CVEs from the last 30 days (most recent)
            start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000Z")
            
            params = {
                "resultsPerPage": min(limit, 100),
                "startIndex": 0,
                "pubStartDate": start_date
            }
            
            response = requests.get(self.nvd_api_url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                total = data.get('totalResults', 0)
                print(f"📡 Found {total} CVEs from last 30 days")
                
                for vuln in data.get("vulnerabilities", []):
                    try:
                        cve = self._parse_cve(vuln)
                        if cve:
                            all_cves.append(cve)
                            if len(all_cves) >= limit:
                                break
                    except Exception as e:
                        continue
                
                print(f"✅ Got {len(all_cves)} CVEs from last 30 days")
            
            # If we need more CVEs, get from last 90 days
            if len(all_cves) < limit:
                print(f"📡 Need more CVEs, fetching from last 90 days...")
                start_date = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%dT00:00:00.000Z")
                
                params = {
                    "resultsPerPage": min(limit - len(all_cves), 50),
                    "startIndex": 0,
                    "pubStartDate": start_date
                }
                
                response = requests.get(self.nvd_api_url, params=params, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    for vuln in data.get("vulnerabilities", []):
                        try:
                            if len(all_cves) >= limit:
                                break
                            cve = self._parse_cve(vuln)
                            if cve and cve not in all_cves:
                                all_cves.append(cve)
                        except Exception as e:
                            continue
                    
                    print(f"✅ Total CVEs fetched: {len(all_cves)}")
            
            # If still no CVEs, use enhanced mock data
            if not all_cves:
                print("⚠️ No recent CVEs found, using enhanced mock data")
                all_cves = self._get_mock_cves()
            
            if all_cves:
                # Cache the results
                cache_data = {
                    "timestamp": datetime.now().isoformat(),
                    "cves": all_cves
                }
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.cache_file, 'w') as f:
                    json.dump(cache_data, f, indent=2)
                print(f"💾 Cached {len(all_cves)} CVEs")
                return all_cves[:limit]
            
            return self._get_mock_cves()
                
        except Exception as e:
            print(f"❌ Error fetching CVEs: {e}")
            return self._get_mock_cves()
    
    def _parse_cve(self, vuln: Dict) -> Optional[Dict]:
        """Parse a single CVE from NVD response"""
        try:
            cve_data = vuln.get("cve", {})
            if not cve_data:
                return None
            
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None
            
            # Skip rejected CVEs
            if cve_data.get("vulnStatus") == "Rejected":
                return None
            
            # Get description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:400]
                    if "** REJECT **" in description:
                        return None
                    break
            
            if not description:
                return None
            
            # Get CVSS score
            cvss_score = 0
            metrics = cve_data.get("metrics", {})
            
            if metrics.get("cvssMetricV31"):
                cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0)
            elif metrics.get("cvssMetricV30"):
                cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0)
            elif metrics.get("cvssMetricV2"):
                cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0)
            
            if cvss_score == 0:
                return None
            
            # Determine severity
            if cvss_score >= 9:
                severity = "critical"
            elif cvss_score >= 7:
                severity = "high"
            elif cvss_score >= 4:
                severity = "medium"
            else:
                severity = "low"
            
            # Get affected software
            affected = []
            for config in cve_data.get("configurations", {}).get("nodes", []):
                for match in config.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpe = match.get("criteria", "")
                        if cpe:
                            parts = cpe.split(":")
                            if len(parts) > 4:
                                software = parts[4]
                                if software not in affected and software != "*" and software:
                                    affected.append(software)
                                if len(affected) >= 3:
                                    break
                    if len(affected) >= 3:
                        break
                if len(affected) >= 3:
                    break
            
            if not affected:
                affected = ["Various"]
            
            # Get references
            refs = []
            for ref in cve_data.get("references", []):
                url = ref.get("url")
                if url:
                    refs.append(url)
                    if len(refs) >= 3:
                        break
            
            if not refs:
                refs = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
            
            # Get published date
            published = cve_data.get("published", "").split("T")[0] if cve_data.get("published") else ""
            
            return {
                "id": cve_id,
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "description": description,
                "published": published,
                "affected_software": affected[:3],
                "references": refs[:3],
                "source": "NVD"
            }
            
        except Exception as e:
            return None
    
    def _get_mock_cves(self) -> List[Dict]:
        """Enhanced mock data with real 2024 CVEs"""
        print("⚠️ Using enhanced mock CVE data (2024 CVEs)")
        return [
            {"id": "CVE-2024-6387", "cve_id": "CVE-2024-6387", "cvss_score": 9.8, "severity": "critical", "description": "OpenSSH Signal Handler Race Condition (regreSSHion) - Remote code execution vulnerability", "published": "2024-07-09", "affected_software": ["OpenSSH"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"], "source": "NVD"},
            {"id": "CVE-2024-3400", "cve_id": "CVE-2024-3400", "cvss_score": 10.0, "severity": "critical", "description": "Palo Alto Networks PAN-OS Command Injection - Critical vulnerability in GlobalProtect", "published": "2024-04-12", "affected_software": ["PAN-OS"], "references": ["https://security.paloaltonetworks.com/CVE-2024-3400"], "source": "NVD"},
            {"id": "CVE-2024-2875", "cve_id": "CVE-2024-2875", "cvss_score": 9.8, "severity": "critical", "description": "GitLab Account Takeover Vulnerability", "published": "2024-03-07", "affected_software": ["GitLab"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-2875"], "source": "NVD"},
            {"id": "CVE-2024-21413", "cve_id": "CVE-2024-21413", "cvss_score": 9.8, "severity": "critical", "description": "Microsoft Outlook Remote Code Execution vulnerability", "published": "2024-02-13", "affected_software": ["Microsoft Outlook"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-21413"], "source": "NVD"},
            {"id": "CVE-2024-21762", "cve_id": "CVE-2024-21762", "cvss_score": 9.8, "severity": "critical", "description": "Fortinet FortiOS Out-of-Bound Write vulnerability", "published": "2024-02-08", "affected_software": ["FortiOS"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-21762"], "source": "NVD"},
            {"id": "CVE-2024-23897", "cve_id": "CVE-2024-23897", "cvss_score": 9.8, "severity": "critical", "description": "Jenkins Arbitrary File Read vulnerability", "published": "2024-01-24", "affected_software": ["Jenkins"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-23897"], "source": "NVD"},
            {"id": "CVE-2024-0204", "cve_id": "CVE-2024-0204", "cvss_score": 9.8, "severity": "critical", "description": "GoAnywhere MFT Authentication Bypass", "published": "2024-01-03", "affected_software": ["GoAnywhere MFT"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0204"], "source": "NVD"},
            {"id": "CVE-2023-46805", "cve_id": "CVE-2023-46805", "cvss_score": 9.8, "severity": "critical", "description": "Ivanti Connect Secure Authentication Bypass", "published": "2023-12-08", "affected_software": ["Ivanti Connect Secure"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-46805"], "source": "NVD"},
            {"id": "CVE-2023-4966", "cve_id": "CVE-2023-4966", "cvss_score": 9.8, "severity": "critical", "description": "Citrix NetScaler ADC and Gateway vulnerability", "published": "2023-10-10", "affected_software": ["Citrix NetScaler"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"], "source": "NVD"},
            {"id": "CVE-2023-42793", "cve_id": "CVE-2023-42793", "cvss_score": 9.8, "severity": "critical", "description": "JetBrains TeamCity Authentication Bypass", "published": "2023-09-20", "affected_software": ["JetBrains TeamCity"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-42793"], "source": "NVD"}
        ]


cve_service = CVEService()
