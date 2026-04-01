"""
AbuseIPDB API Service
Provides IP reputation and abuse reporting
"""

import os
import requests
from typing import Dict, Any, List
from datetime import datetime

class AbuseIPDBService:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "d685053d61dbf5add2b54a2be39ae8ce57f80d9ab8ddacc460823778b0b109b88cc60a7a38f9c21e")
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
    
    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Check IP address for abuse reports
        
        Args:
            ip_address: The IP address to check
            max_age_days: Maximum age of reports to include (default 90)
        """
        endpoint = f"{self.base_url}/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": ""
        }
        
        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return self._format_check_response(data, ip_address)
            elif response.status_code == 404:
                return {
                    "success": False,
                    "error": "IP not found or no reports available",
                    "ip": ip_address
                }
            elif response.status_code == 429:
                return {
                    "success": False,
                    "error": "Rate limit exceeded. Please wait and try again.",
                    "ip": ip_address
                }
            else:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code} - {response.text}",
                    "ip": ip_address
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "ip": ip_address
            }
    
    def check_ip_batch(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """
        Check multiple IP addresses at once
        Maximum 1000 IPs per request
        """
        endpoint = f"{self.base_url}/check-block"
        ip_list = ",".join(ip_addresses[:1000])  # Limit to 1000
        
        params = {
            "ipAddress": ip_list
        }
        
        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "source": "abuseipdb",
                    "type": "ip_batch",
                    "results": data.get("data", {}).get("IPs", []),
                    "count": len(data.get("data", {}).get("IPs", []))
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
    
    def get_recent_reports(self, limit: int = 100, page: int = 1) -> Dict[str, Any]:
        """
        Get recent abuse reports
        """
        endpoint = f"{self.base_url}/reports"
        params = {
            "page": page,
            "perPage": min(limit, 1000)
        }
        
        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "source": "abuseipdb",
                    "type": "reports",
                    "reports": data.get("data", []),
                    "total": data.get("meta", {}).get("total", 0),
                    "page": page
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
    
    def get_blocklist(self, confidence_minimum: int = 50, limit: int = 10000) -> Dict[str, Any]:
        """
        Get blocklist of reported IPs
        """
        endpoint = f"{self.base_url}/blocklist"
        params = {
            "confidenceMinimum": confidence_minimum,
            "limit": min(limit, 10000)
        }
        
        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "source": "abuseipdb",
                    "type": "blocklist",
                    "count": len(data.get("data", [])),
                    "blocklist": data.get("data", [])
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
    
    def report_ip(self, ip_address: str, categories: List[int], comment: str = "") -> Dict[str, Any]:
        """
        Report an IP for abuse
        
        Args:
            ip_address: The IP address to report
            categories: List of category numbers (1-25)
            comment: Optional comment about the abuse
        """
        endpoint = f"{self.base_url}/report"
        data = {
            "ip": ip_address,
            "categories": ",".join(map(str, categories)),
            "comment": comment
        }
        
        try:
            response = requests.post(endpoint, headers=self.headers, data=data, timeout=30)
            
            if response.status_code == 201:
                return {
                    "success": True,
                    "message": "Report submitted successfully",
                    "ip": ip_address
                }
            else:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code} - {response.text}"
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _format_check_response(self, data: Dict, ip_address: str) -> Dict[str, Any]:
        """Format IP check response"""
        ip_data = data.get("data", {})
        
        # Parse abuse reports
        abuse_reports = ip_data.get("abuseReports", [])
        formatted_reports = []
        for report in abuse_reports[:10]:  # Top 10 recent
            formatted_reports.append({
                "reporter_id": report.get("reporterId", 0),
                "category": report.get("category", 0),
                "timestamp": report.get("date", ""),
                "comment": report.get("comment", "")
            })
        
        # Get category breakdown
        categories = ip_data.get("reports", [])
        category_counts = {}
        for cat in categories:
            cat_id = cat.get("category", 0)
            category_counts[cat_id] = category_counts.get(cat_id, 0) + 1
        
        return {
            "success": True,
            "source": "abuseipdb",
            "type": "ip_check",
            "query": ip_address,
            "ip_address": ip_data.get("ipAddress", ""),
            "version": ip_data.get("ipVersion", 0),
            "is_public": ip_data.get("isPublic", False),
            "ip_rating": ip_data.get("ipRating", ""),
            "abuse_confidence_score": ip_data.get("abuseConfidenceScore", 0),
            "country_code": ip_data.get("countryCode", ""),
            "country_name": ip_data.get("countryName", ""),
            "region": ip_data.get("regionName", ""),
            "city": ip_data.get("city", ""),
            "isp": ip_data.get("isp", ""),
            "domain": ip_data.get("domain", ""),
            "total_reports": ip_data.get("numDistinctUsers", 0),
            "total_reports_count": ip_data.get("totalReports", 0),
            "last_reported_at": ip_data.get("lastReportedAt", ""),
            "is_whitelisted": ip_data.get("isWhitelisted", False),
            "is_tor": ip_data.get("isTor", False),
            "is_proxy": ip_data.get("isProxy", False),
            "is_vpn": ip_data.get("isVpn", False),
            "is_relay": ip_data.get("isRelay", False),
            "is_datacenter": ip_data.get("isDatacenter", False),
            "recent_reports": formatted_reports,
            "category_counts": category_counts
        }


# Category mapping for reference
ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}


# Singleton instance
abuseipdb_service = AbuseIPDBService()
