"""
CWE Service - Fetches and manages Common Weakness Enumeration data from MITRE
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CWEService:
    """Service for fetching and managing CWE data from MITRE"""
    
    def __init__(self):
        self.cache_file = Path(__file__).parent.parent / "data" / "cwe_complete.json"
        logger.info(f"Looking for CWE data at: {self.cache_file}")
        
    def fetch_all_cwes(self) -> List[Dict]:
        """Fetch all CWE weaknesses from the complete MITRE database"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    cwes = json.load(f)
                    logger.info(f"✅ Loaded {len(cwes)} CWEs from MITRE database")
                    return cwes
            else:
                logger.warning(f"CWE database file not found at {self.cache_file}")
                return self._get_basic_cwes()
                
        except Exception as e:
            logger.error(f"Error loading CWE data: {e}")
            return self._get_basic_cwes()
    
    def get_cwe_details(self, cwe_id: str) -> Optional[Dict]:
        """Get details for a specific CWE"""
        all_cwes = self.fetch_all_cwes()
        for cwe in all_cwes:
            if cwe.get("id") == cwe_id:
                return cwe
        return None
    
    def search_cwes(self, query: str) -> List[Dict]:
        """Search CWEs by ID, name, or description"""
        all_cwes = self.fetch_all_cwes()
        query_lower = query.lower()
        return [c for c in all_cwes 
                if query_lower in c["id"].lower() 
                or query_lower in c["name"].lower()
                or (c.get("description") and query_lower in c["description"].lower())]
    
    def get_cwes_by_severity(self, severity: str) -> List[Dict]:
        """Get CWEs by severity level"""
        all_cwes = self.fetch_all_cwes()
        return [c for c in all_cwes if c.get("severity") == severity]
    
    def get_cwe_stats(self) -> Dict:
        """Get CWE statistics"""
        all_cwes = self.fetch_all_cwes()
        return {
            "total": len(all_cwes),
            "critical": len([c for c in all_cwes if c.get("severity") == "critical"]),
            "high": len([c for c in all_cwes if c.get("severity") == "high"]),
            "medium": len([c for c in all_cwes if c.get("severity") == "medium"])
        }
    
    def _get_basic_cwes(self) -> List[Dict]:
        """Return basic CWE list as fallback"""
        return [
            {"id": "CWE-89", "name": "SQL Injection", "severity": "critical", "description": "Improper Neutralization of Special Elements used in an SQL Command"},
            {"id": "CWE-79", "name": "Cross-site Scripting (XSS)", "severity": "high", "description": "Improper Neutralization of Input During Web Page Generation"},
            {"id": "CWE-78", "name": "OS Command Injection", "severity": "critical", "description": "Improper Neutralization of Special Elements used in an OS Command"},
        ]


cwe_service = CWEService()
