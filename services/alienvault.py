"""
AlienVault OTX - Free threat intelligence feeds
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


class AlienVaultService:
    """AlienVault OTX - Free threat intelligence feeds"""
    
    def __init__(self):
        pass
    
    def get_malicious_ips(self, limit: int = 200) -> List[Dict]:
        """Get malicious IPs from AlienVault OTX public feeds"""
        cache_file = CACHE_DIR / "alienvault_ips.json"
        
        if cache_file.exists():
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if (datetime.now() - mtime).seconds < CACHE_EXPIRY:
                with open(cache_file) as f:
                    return json.load(f)
        
        ips = []
        
        # Feed 1: FireHOL Level 1 IPs (reliable, updated regularly)
        try:
            print("Fetching FireHOL IP lists for AlienVault...")
            response = requests.get(
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                timeout=30
            )
            if response.status_code == 200:
                lines = response.text.strip().split("\n")
                count = 0
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            ipaddress.ip_network(line, strict=False)
                            ips.append({
                                "id": f"alienvault_firehol_{count}",
                                "type": "ip",
                                "value": line,
                                "severity": "high",
                                "confidence": 85,
                                "first_seen": datetime.now().isoformat(),
                                "last_seen": datetime.now().isoformat(),
                                "source": "alienvault",
                                "tags": ["malicious", "blocklist"],
                                "description": "AlienVault OTX: FireHOL malicious IP"
                            })
                            count += 1
                            if count >= limit:
                                break
                        except:
                            continue
            print(f"AlienVault FireHOL IPs: {count}")
        except Exception as e:
            print(f"AlienVault FireHOL error: {e}")
        
        # Save to cache
        with open(cache_file, "w") as f:
            json.dump(ips, f)
        
        return ips
    
    def get_malicious_urls(self, limit: int = 200) -> List[Dict]:
        """Get malicious URLs from working feeds"""
        cache_file = CACHE_DIR / "alienvault_urls.json"
        
        if cache_file.exists():
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if (datetime.now() - mtime).seconds < CACHE_EXPIRY:
                with open(cache_file) as f:
                    return json.load(f)
        
        urls = []
        
        # Use OpenPhish for phishing URLs
        try:
            print("Fetching OpenPhish URLs for AlienVault...")
            response = requests.get(
                "https://openphish.com/feed.txt",
                timeout=30
            )
            if response.status_code == 200:
                lines = response.text.strip().split("\n")
                for i, line in enumerate(lines[:limit]):
                    line = line.strip()
                    if line and line.startswith("http"):
                        urls.append({
                            "id": f"alienvault_openphish_{i}",
                            "type": "url",
                            "value": line,
                            "severity": "high",
                            "confidence": 85,
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat(),
                            "source": "alienvault",
                            "tags": ["phishing"],
                            "description": "AlienVault OTX: Phishing URL"
                        })
            print(f"AlienVault OpenPhish URLs: {len(urls)}")
        except Exception as e:
            print(f"AlienVault OpenPhish error: {e}")
        
        with open(cache_file, "w") as f:
            json.dump(urls, f)
        
        return urls


alienvault_service = AlienVaultService()
