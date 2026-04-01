"""
VirusTotal API Service
Provides IP, domain, and file reputation checking
"""

import os
import requests
from typing import Dict, Any, Optional

class VirusTotalService:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "a2dda23900cf276184c16f369870729e3adb5ac3cbe9761b58e57e3b8475b382")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
    
    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation on VirusTotal"""
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return self._format_ip_response(data)
            elif response.status_code == 404:
                return {
                    "success": False,
                    "error": "IP not found in VirusTotal database",
                    "ip": ip_address
                }
            else:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code}",
                    "ip": ip_address
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "ip": ip_address
            }
    
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation on VirusTotal"""
        url = f"{self.base_url}/domains/{domain}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return self._format_domain_response(data)
            elif response.status_code == 404:
                return {
                    "success": False,
                    "error": "Domain not found in VirusTotal database",
                    "domain": domain
                }
            else:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code}",
                    "domain": domain
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }
    
    def check_file(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash (MD5, SHA1, SHA256) on VirusTotal"""
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return self._format_file_response(data)
            elif response.status_code == 404:
                return {
                    "success": False,
                    "error": "File hash not found in VirusTotal database",
                    "hash": file_hash
                }
            else:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code}",
                    "hash": file_hash
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "hash": file_hash
            }
    
    def submit_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        url_scan_endpoint = f"{self.base_url}/urls"
        
        try:
            response = requests.post(
                url_scan_endpoint,
                headers=self.headers,
                data={"url": url},
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "scan_id": data.get("data", {}).get("id", ""),
                    "url": url
                }
            else:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code}",
                    "url": url
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "url": url
            }
    
    def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get URL analysis report"""
        import urllib.parse
        encoded_url = urllib.parse.quote(url, safe='')
        url = f"{self.base_url}/urls/{encoded_url}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return self._format_url_response(data)
            elif response.status_code == 404:
                return {
                    "success": False,
                    "error": "URL not found in VirusTotal database"
                }
            else:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code}"
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _format_ip_response(self, data: Dict) -> Dict[str, Any]:
        """Format IP response data"""
        attributes = data.get("data", {}).get("attributes", {})
        
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        last_analysis_results = attributes.get("last_analysis_results", {})
        
        # Get malicious vendors
        malicious_vendors = []
        for vendor, result in last_analysis_results.items():
            if result.get("category") == "malicious":
                malicious_vendors.append({
                    "vendor": vendor,
                    "result": result.get("result", "malicious"),
                    "method": result.get("method", ""),
                    "engine_version": result.get("engine_version", "")
                })
        
        return {
            "success": True,
            "source": "virustotal",
            "type": "ip_address",
            "query": attributes.get("ip_address", ""),
            "country": attributes.get("country", ""),
            "as_owner": attributes.get("as_owner", ""),
            "network": attributes.get("network", ""),
            "stats": {
                "harmless": last_analysis_stats.get("harmless", 0),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "timeout": last_analysis_stats.get("timeout", 0),
                "total": sum(last_analysis_stats.values())
            },
            "reputation": attributes.get("reputation", 0),
            "last_analysis_date": attributes.get("last_analysis_date", 0),
            "last_analysis_results": malicious_vendors[:10],  # Top 10 malicious
            "tags": attributes.get("tags", []),
            "context": attributes.get("context_attributes", {})
        }
    
    def _format_domain_response(self, data: Dict) -> Dict[str, Any]:
        """Format domain response data"""
        attributes = data.get("data", {}).get("attributes", {})
        
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        last_analysis_results = attributes.get("last_analysis_results", {})
        
        # Get malicious vendors
        malicious_vendors = []
        for vendor, result in last_analysis_results.items():
            if result.get("category") == "malicious":
                malicious_vendors.append({
                    "vendor": vendor,
                    "result": result.get("result", "malicious"),
                    "method": result.get("method", "")
                })
        
        return {
            "success": True,
            "source": "virustotal",
            "type": "domain",
            "query": attributes.get("id", ""),
            "creation_date": attributes.get("creation_date", 0),
            "last_modified": attributes.get("last_modification_date", 0),
            "registrar": attributes.get("registrar", ""),
            "stats": {
                "harmless": last_analysis_stats.get("harmless", 0),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "timeout": last_analysis_stats.get("timeout", 0),
                "total": sum(last_analysis_stats.values())
            },
            "last_analysis_date": attributes.get("last_analysis_date", 0),
            "last_analysis_results": malicious_vendors[:10],
            "tags": attributes.get("tags", []),
            "whois": attributes.get("whois", "")
        }
    
    def _format_file_response(self, data: Dict) -> Dict[str, Any]:
        """Format file response data"""
        attributes = data.get("data", {}).get("attributes", {})
        
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        return {
            "success": True,
            "source": "virustotal",
            "type": "file",
            "query": attributes.get("sha256", ""),
            "sha256": attributes.get("sha256", ""),
            "sha1": attributes.get("sha1", ""),
            "md5": attributes.get("md5", ""),
            "file_type": attributes.get("file_type", ""),
            "file_size": attributes.get("size", 0),
            "stats": {
                "harmless": last_analysis_stats.get("harmless", 0),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "total": sum(last_analysis_stats.values())
            },
            "last_analysis_date": attributes.get("last_analysis_date", 0),
            "tags": attributes.get("tags", []),
            "meaningful_names": attributes.get("meaningful_names", []),
            "magic": attributes.get("magic", "")
        }
    
    def _format_url_response(self, data: Dict) -> Dict[str, Any]:
        """Format URL response data"""
        attributes = data.get("data", {}).get("attributes", {})
        
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        return {
            "success": True,
            "source": "virustotal",
            "type": "url",
            "url": attributes.get("url", ""),
            "stats": {
                "harmless": last_analysis_stats.get("harmless", 0),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "total": sum(last_analysis_stats.values())
            },
            "last_analysis_date": attributes.get("last_analysis_date", 0),
            "tags": attributes.get("tags", [])
        }


# Singleton instance
vt_service = VirusTotalService()
