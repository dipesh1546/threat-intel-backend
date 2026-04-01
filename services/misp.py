"""
Threat Intelligence Service - Using working public feeds
"""

import requests
import json
from typing import Dict, List
from datetime import datetime
from pathlib import Path
import ipaddress

CACHE_DIR = Path(__file__).parent.parent / "data" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

CACHE_EXPIRY = 3600  # 1 hour cache


class MISPService:
    """Threat Intelligence using working public feeds"""
    
    def __init__(self):
        pass
    
    def is_valid_ip_or_cidr(self, value: str) -> bool:
        """Check if string is a valid IP address or CIDR range"""
        if not value or value.startswith('#'):
            return False
        try:
            # Try to parse as network (supports both IP and CIDR)
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False
    
    def get_malicious_ips(self, limit: int = 500) -> List[Dict]:
        """Get malicious IPs from working public feeds"""
        cache_file = CACHE_DIR / "misp_malicious_ips.json"
        
        # Check cache
        if cache_file.exists():
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if (datetime.now() - mtime).seconds < CACHE_EXPIRY:
                with open(cache_file) as f:
                    return json.load(f)
        
        ips = []
        print("Fetching threat IPs...")
        
        # Feed 1: FireHOL Level 1 IPs
        try:
            response = requests.get(
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                timeout=30
            )
            if response.status_code == 200:
                lines = response.text.strip().split("\n")
                count = 0
                for line in lines:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Validate IP/CIDR
                    try:
                        ipaddress.ip_network(line, strict=False)
                        ips.append({
                            "id": f"firehol_{count}",
                            "type": "ip",
                            "value": line,
                            "severity": "high",
                            "confidence": 85,
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat(),
                            "source": "firehol",
                            "tags": ["malicious", "blocklist"],
                            "description": "FireHOL: Known malicious IP/CIDR"
                        })
                        count += 1
                        if count >= limit:
                            break
                    except:
                        continue
                print(f"FireHOL: {count} IPs")
        except Exception as e:
            print(f"FireHOL error: {e}")
        
        # Feed 2: Blocklist.de
        try:
            response = requests.get(
                "https://lists.blocklist.de/lists/all.txt",
                timeout=30
            )
            if response.status_code == 200:
                lines = response.text.strip().split("\n")
                count = 0
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        ipaddress.ip_network(line, strict=False)
                        ips.append({
                            "id": f"blocklist_{count}",
                            "type": "ip",
                            "value": line,
                            "severity": "medium",
                            "confidence": 75,
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat(),
                            "source": "blocklist",
                            "tags": ["attacker", "malicious"],
                            "description": "Blocklist.de: Known attacker IP"
                        })
                        count += 1
                        if count >= limit:
                            break
                    except:
                        continue
                print(f"Blocklist.de: {count} IPs")
        except Exception as e:
            print(f"Blocklist.de error: {e}")
        
        # Save to cache
        with open(cache_file, "w") as f:
            json.dump(ips, f)
        print(f"Total IPs saved to cache: {len(ips)}")
        
        return ips
    
    def get_malicious_domains(self, limit: int = 200) -> List[Dict]:
        """Get malicious domains from working feeds"""
        cache_file = CACHE_DIR / "misp_malicious_domains.json"
        
        if cache_file.exists():
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if (datetime.now() - mtime).seconds < CACHE_EXPIRY:
                with open(cache_file) as f:
                    return json.load(f)
        
        domains = []
        
        try:
            response = requests.get(
                "https://urlhaus-api.abuse.ch/v1/hosts/recent/",
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                for i, host in enumerate(data.get("hosts", [])[:limit]):
                    if host.get("host"):
                        domains.append({
                            "id": f"urlhaus_domain_{i}",
                            "type": "domain",
                            "value": host.get("host", ""),
                            "severity": "high",
                            "confidence": 85,
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat(),
                            "source": "urlhaus",
                            "tags": ["malware", "malicious"],
                            "description": "URLhaus: Malware distribution domain"
                        })
            print(f"URLhaus domains: {len(domains)}")
        except Exception as e:
            print(f"URLhaus domains error: {e}")
        
        with open(cache_file, "w") as f:
            json.dump(domains, f)
        
        return domains


misp_service = MISPService()
