import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, EmailStr
import json
import re
import asyncio
import random
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from contextlib import asynccontextmanager
import time
from functools import wraps
import logging
import os
import tempfile
import hashlib
from fastapi import File, UploadFile
import requests
from typing import Dict, Any  # Add this line

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import services
from services.virustotal import vt_service
from services.abuseipdb import abuseipdb_service
from services.threat_feeds import threat_aggregator
from services.auth_service import auth_service
from services.websocket_manager import websocket_manager
from services.cve_cisa_service import cve_service
from services.report_service import report_service
from services.cwe_service import cwe_service

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Create limiter
limiter = Limiter(key_func=get_remote_address)

# Create FastAPI app with lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events"""
    # Startup
    logger.info("Starting up...")
    asyncio.create_task(broadcast_threat_updates())
    logger.info("WebSocket background task started")
    yield
    # Shutdown
    logger.info("Shutting down...")

app = FastAPI(
    title="NepalThreat Intel API",
    description="Threat Intelligence Dashboard Backend API",
    version="1.0.0",
    lifespan=lifespan
)

# Add rate limit exception handler
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load mock data
DATA_DIR = Path(__file__).parent / "data"

def load_mock_data():
    """Load mock data from JSON file"""
    data_file = DATA_DIR / "mock_data.json"
    if data_file.exists():
        with open(data_file, 'r') as f:
            return json.load(f)
    return get_default_data()

def get_default_data():
    """Return default mock data"""
    return {
        "stats": {
            "threat_level": 72,
            "active_threats": 1247,
            "critical_count": 23,
            "high_count": 89,
            "medium_count": 312,
            "low_count": 823,
            "total_iocs": 15420,
            "total_cves": 3428,
            "total_actors": 156
        },
        "alerts": [],
        "iocs": [],
        "cves": [],
        "actors": [],
        "attack_trends": [],
        "country_attacks": []
    }

# Request models
class ScanRequest(BaseModel):
    query: str
    scan_type: str = "auto"

class VirusTotalRequest(BaseModel):
    ip: str = None
    domain: str = None
    url: str = None
    file_hash: str = None

class AbuseIPDBRequest(BaseModel):
    ip: str
    max_age_days: int = 90

# Initialize data
mock_data = load_mock_data()

# Initialize real-time threat data
real_threat_data = threat_aggregator.get_all_iocs()

# API Routes

@app.get("/")
async def root():
    return {"message": "NepalThreat Intel API", "version": "1.0.0"}

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics from real threat feeds - CACHED"""
    return threat_aggregator.get_dashboard_stats()

@app.get("/api/threats")
async def get_threats(
    severity: str = None,
    attack_type: str = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500)
):
    """Get threat alerts with pagination"""
    alerts = threat_aggregator.get_recent_alerts()
    
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    if attack_type:
        alerts = [a for a in alerts if a.get("type") == attack_type]
    
    # Pagination
    start = (page - 1) * limit
    end = start + limit
    paginated_alerts = alerts[start:end]
    
    return {
        "total": len(alerts),
        "page": page,
        "limit": limit,
        "total_pages": (len(alerts) + limit - 1) // limit,
        "data": paginated_alerts
    }

@app.post("/api/threat-feeds/check")
async def check_threat_feed(request: dict, authorization: str = Header(None)):
    """Check if a URL/IP appears in threat intelligence feeds"""
    query = request.get("query", "")
    if not query:
        return JSONResponse(status_code=400, content={"error": "Query required"})
    
    # Check all IOCs (limit search for performance)
    all_iocs = threat_aggregator.get_all_iocs()
    
    # Check URLs (limit to first 500 for performance)
    for url in all_iocs.get("urls", [])[:500]:
        if url.get("value") == query or query in url.get("value", ""):
            return {
                "is_malicious": True,
                "source": url.get("source", "Threat Feed"),
                "threat_type": "phishing" if "phish" in url.get("source", "").lower() else "malicious_url",
                "confidence": url.get("confidence", 85),
                "description": url.get("description", "Malicious URL detected in threat feed")
            }
    
    # Check IPs (limit to first 500 for performance)
    for ip in all_iocs.get("ips", [])[:500]:
        if ip.get("value") == query:
            return {
                "is_malicious": True,
                "source": ip.get("source", "Threat Feed"),
                "threat_type": "malicious_ip",
                "confidence": ip.get("confidence", 85),
                "description": ip.get("description", "Malicious IP detected in threat feed")
            }
    
    # Check Domains (limit to first 500 for performance)
    for domain in all_iocs.get("domains", [])[:500]:
        if domain.get("value") == query or query in domain.get("value", ""):
            return {
                "is_malicious": True,
                "source": domain.get("source", "Threat Feed"),
                "threat_type": "malicious_domain",
                "confidence": domain.get("confidence", 75),
                "description": domain.get("description", "Malicious domain detected in threat feed")
            }
    
    return {"is_malicious": False}

@app.get("/api/threats/nepal")
async def get_nepal_threats(
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500)
):
    """Get Nepal-specific threat alerts with pagination"""
    from services.threat_feeds import filter_nepal_threats
    
    # Get all IOCs
    all_iocs = threat_aggregator.get_all_iocs()
    
    # Filter for Nepal-specific threats
    nepal_iocs = filter_nepal_threats(all_iocs)
    
    # Convert IOCs to alerts
    alerts = []
    
    # Add IPs
    for ip in nepal_iocs.get("ips", []):
        alerts.append({
            "id": ip.get("id", ""),
            "type": "malicious_ip",
            "severity": ip.get("severity", "high"),
            "title": f"Malicious IP from {ip.get('source', 'threat feed')}",
            "description": ip.get("description", "Malicious IP address from global threat feed"),
            "source_ip": ip.get("value", ""),
            "source_country": ip.get("country", "Unknown"),
            "target_ip": "",
            "target_country": "NP",
            "timestamp": ip.get("last_seen", datetime.now().isoformat())
        })
    
    # Add URLs
    for url in nepal_iocs.get("urls", []):
        alerts.append({
            "id": url.get("id", ""),
            "type": "phishing",
            "severity": url.get("severity", "high"),
            "title": "Nepal-Targeted Phishing URL",
            "description": url.get("description", "Phishing URL potentially targeting Nepal"),
            "source_ip": url.get("value", ""),
            "source_country": "Unknown",
            "target_ip": "",
            "target_country": "NP",
            "timestamp": url.get("last_seen", datetime.now().isoformat())
        })
    
    # Sort by timestamp (newest first)
    alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    # Pagination
    total = len(alerts)
    start = (page - 1) * limit
    end = start + limit
    paginated_alerts = alerts[start:end]
    
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": (total + limit - 1) // limit,
        "data": paginated_alerts
    }

@app.get("/api/threats/{alert_id}")
async def get_threat(alert_id: str):
    """Get specific threat alert"""
    alerts = mock_data.get("alerts", [])
    for alert in alerts:
        if alert.get("id") == alert_id:
            return alert
    return {"error": "Alert not found"}, 404

@app.get("/api/iocs")
async def get_iocs(
    ioc_type: str = None,
    severity: str = None,
    search: str = None,
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500)
):
    """Get IOC database entries with pagination"""
    all_iocs = threat_aggregator.get_all_iocs()
    
    # Combine all IOC types
    iocs = []
    iocs.extend(all_iocs.get("urls", []))
    iocs.extend(all_iocs.get("ips", []))
    iocs.extend(all_iocs.get("domains", []))
    iocs.extend(all_iocs.get("hashes", []))
    
    if ioc_type:
        iocs = [i for i in iocs if i.get("type") == ioc_type]
    if severity:
        iocs = [i for i in iocs if i.get("severity") == severity]
    if search:
        search_lower = search.lower()
        iocs = [i for i in iocs if search_lower in i.get("value", "").lower() or 
                search_lower in i.get("id", "").lower()]
    
    # Pagination
    start = (page - 1) * limit
    end = start + limit
    paginated_iocs = iocs[start:end]
    
    return {
        "total": len(iocs),
        "page": page,
        "limit": limit,
        "total_pages": (len(iocs) + limit - 1) // limit,
        "data": paginated_iocs
    }

@app.post("/api/iocs")
async def add_ioc(request: dict, authorization: str = Header(None)):
    """Add a new IOC"""
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        iocs_file = DATA_DIR / "custom_iocs.json"
        iocs = []
        if iocs_file.exists():
            with open(iocs_file, 'r') as f:
                iocs = json.load(f)
        
        new_ioc = {
            "id": f"custom_{len(iocs) + 1}",
            "value": request.get("value"),
            "type": request.get("type"),
            "severity": request.get("severity"),
            "confidence": request.get("confidence", 50),
            "tags": request.get("tags", []),
            "description": request.get("description", ""),
            "source": "user_added",
            "created_by": user["email"],
            "first_seen": request.get("first_seen", datetime.now().isoformat()),
            "last_seen": request.get("last_seen", datetime.now().isoformat())
        }
        
        iocs.append(new_ioc)
        
        with open(iocs_file, 'w') as f:
            json.dump(iocs, f, indent=2)
        
        return {"success": True, "message": "IOC added successfully", "ioc": new_ioc}
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/iocs/import")
async def import_iocs(request: dict, authorization: str = Header(None)):
    """Import IOCs from file"""
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        imported_iocs = request.get("iocs", [])
        iocs_file = DATA_DIR / "custom_iocs.json"
        iocs = []
        if iocs_file.exists():
            with open(iocs_file, 'r') as f:
                iocs = json.load(f)
        
        for ioc in imported_iocs:
            new_ioc = {
                "id": f"custom_{len(iocs) + 1}",
                "value": ioc.get("value") or ioc.get("Value"),
                "type": ioc.get("type") or ioc.get("Type"),
                "severity": ioc.get("severity") or ioc.get("Severity", "medium"),
                "confidence": int(ioc.get("confidence") or ioc.get("Confidence", 50)),
                "tags": ioc.get("tags", "").split(";") if isinstance(ioc.get("tags"), str) else ioc.get("tags", []),
                "source": "imported",
                "created_by": user["email"],
                "last_seen": datetime.now().isoformat()
            }
            iocs.append(new_ioc)
        
        with open(iocs_file, 'w') as f:
            json.dump(iocs, f, indent=2)
        
        return {"success": True, "message": f"Imported {len(imported_iocs)} IOCs successfully"}
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/api/iocs/{ioc_id}")
async def delete_ioc(ioc_id: str, authorization: str = Header(None)):
    """Delete an IOC"""
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        iocs_file = DATA_DIR / "custom_iocs.json"
        iocs = []
        if iocs_file.exists():
            with open(iocs_file, 'r') as f:
                iocs = json.load(f)
        
        iocs = [i for i in iocs if i.get("id") != ioc_id]
        
        with open(iocs_file, 'w') as f:
            json.dump(iocs, f, indent=2)
        
        return {"success": True, "message": "IOC deleted successfully"}
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/iocs/search")
async def search_iocs(request: dict):
    """Search IOCs with advanced filters (limit results for performance)"""
    iocs = mock_data.get("iocs", [])
    
    # Also include custom IOCs
    custom_iocs_file = DATA_DIR / "custom_iocs.json"
    if custom_iocs_file.exists():
        with open(custom_iocs_file, 'r') as f:
            custom_iocs = json.load(f)
            iocs.extend(custom_iocs)
    
    query = request.get("query", "")
    ioc_type = request.get("type")
    severity = request.get("severity")
    tags = request.get("tags", [])
    
    if query:
        query_lower = query.lower()
        iocs = [i for i in iocs if query_lower in i.get("value", "").lower() or 
                query_lower in i.get("id", "").lower()]
    
    if ioc_type:
        iocs = [i for i in iocs if i.get("type") == ioc_type]
    if severity:
        iocs = [i for i in iocs if i.get("severity") == severity]
    if tags:
        iocs = [i for i in iocs if any(t in i.get("tags", []) for t in tags)]
    
    # Limit search results to 500 for performance
    return iocs[:500]

@app.get("/api/attack-vectors")
async def get_attack_vectors(
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500)
):
    """Get attack vectors with pagination"""
    # Get all IOCs
    all_iocs = threat_aggregator.get_all_iocs()
    
    attack_vectors = []
    provinces = ["Bagmati", "Province 1", "Madhesh", "Gandaki", "Lumbini", "Karnali", "Sudurpashchim"]
    
    # Process IPs (limit for performance)
    for ip in all_iocs.get("ips", [])[:2000]:
        source_country = ip.get("country", "Unknown")
        if not source_country or source_country == "Unknown":
            source_country = random.choice(["Russia", "China", "North Korea", "Vietnam", "India", "US"])
        
        attack_vectors.append({
            "id": ip.get("id", ""),
            "type": "Malicious IP",
            "severity": ip.get("severity", "high"),
            "source": source_country,
            "target": random.choice(provinces),
            "targetProvince": random.choice(provinces),
            "timestamp": ip.get("last_seen", datetime.now().isoformat()),
            "value": ip.get("value", ""),
            "description": ip.get("description", "Malicious IP detected")
        })
    
    # Process URLs (limit for performance)
    for url in all_iocs.get("urls", [])[:2000]:
        attack_vectors.append({
            "id": url.get("id", ""),
            "type": "Phishing URL",
            "severity": url.get("severity", "high"),
            "source": url.get("source", "Unknown"),
            "target": "Nepal",
            "targetProvince": random.choice(provinces),
            "timestamp": url.get("last_seen", datetime.now().isoformat()),
            "value": url.get("value", ""),
            "description": url.get("description", "Phishing attempt detected")
        })
    
    # Process domains (limit for performance)
    for domain in all_iocs.get("domains", [])[:2000]:
        attack_vectors.append({
            "id": domain.get("id", ""),
            "type": "Malicious Domain",
            "severity": domain.get("severity", "medium"),
            "source": domain.get("source", "Unknown"),
            "target": "Nepal",
            "targetProvince": random.choice(provinces),
            "timestamp": domain.get("last_seen", datetime.now().isoformat()),
            "value": domain.get("value", ""),
            "description": domain.get("description", "Malicious domain detected")
        })
    
    # Sort by timestamp
    attack_vectors.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    # Pagination
    start = (page - 1) * limit
    end = start + limit
    paginated_vectors = attack_vectors[start:end]
    
    return {
        "total": len(attack_vectors),
        "page": page,
        "limit": limit,
        "total_pages": (len(attack_vectors) + limit - 1) // limit,
        "data": paginated_vectors
    }

@app.get("/api/cves")
async def get_cves(
    severity: str = None,
    search: str = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    refresh: bool = False
):
    """Get CVE alerts with pagination"""
    print(f"=== GET /api/cves called ===")

    if refresh:
        cache_file = DATA_DIR / "cve_cisa_cache.json"
        if cache_file.exists():
            cache_file.unlink()
        print("CVE cache cleared, fetching fresh data...")

    all_cves = cve_service.fetch_all_cves()
    print(f"Retrieved {len(all_cves)} CVEs from CISA KEV service")

    cves = all_cves
    if severity and severity != "all":
        cves = [c for c in cves if c["severity"] == severity]
    if search:
        search_lower = search.lower()
        cves = [c for c in cves if search_lower in c["cve_id"].lower() or 
                search_lower in c["description"].lower()]

    # Pagination
    start = (page - 1) * limit
    end = start + limit
    paginated_cves = cves[start:end]
    
    return {
        "total": len(cves),
        "page": page,
        "limit": limit,
        "total_pages": (len(cves) + limit - 1) // limit,
        "data": paginated_cves
    }

@app.post("/api/cves/refresh")
async def refresh_cves(authorization: str = Header(None)):
    """Manually refresh CVE data"""
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        cache_file = DATA_DIR / "cve_cisa_cache.json"
        if cache_file.exists():
            cache_file.unlink()
        
        cves = cve_service.fetch_all_cves()
        
        return {
            "success": True,
            "message": f"Refreshed {len(cves)} CVEs from CISA KEV",
            "count": len(cves),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error refreshing CVEs: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============================================
# CWE Service Endpoint
# ============================================

@app.get("/api/cwe-list")
async def get_cwe_list(
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500)
):
    """Get CWE weaknesses with pagination"""
    try:
        all_cwes = cwe_service.fetch_all_cwes()
        
        # Pagination
        start = (page - 1) * limit
        end = start + limit
        paginated_cwes = all_cwes[start:end]
        
        return {
            "total": len(all_cwes),
            "page": page,
            "limit": limit,
            "total_pages": (len(all_cwes) + limit - 1) // limit,
            "data": paginated_cwes
        }
    except Exception as e:
        logger.error(f"Error fetching CWE list: {e}")
        return {"total": 0, "data": []}

# ============================================
# Vendors & Products Endpoint
# ============================================

@app.get("/api/vendors-products")
async def get_vendors_products():
    """Get vendors and products statistics from CVEs (with limits for performance)"""
    all_cves = cve_service.fetch_all_cves()
    
    vendor_stats = defaultdict(lambda: {
        "productCount": 0,
        "cveCount": 0,
        "criticalCount": 0,
        "highCount": 0,
        "products": set()
    })
    
    product_stats = defaultdict(lambda: {
        "vendor": "",
        "cveCount": 0,
        "criticalCount": 0,
        "highCount": 0,
        "lastCVE": ""
    })
    
    for cve in all_cves[:2000]:  # Limit to 2000 CVEs for performance
        for software in cve.get("affected_software", []):
            parts = software.split(" ")
            vendor = parts[0] if parts else "Unknown"
            
            vendor_stats[vendor]["cveCount"] += 1
            vendor_stats[vendor]["products"].add(software)
            if cve.get("severity") == "critical":
                vendor_stats[vendor]["criticalCount"] += 1
            if cve.get("severity") == "high":
                vendor_stats[vendor]["highCount"] += 1
            
            product_key = f"{vendor}:{software}"
            product_stats[product_key]["vendor"] = vendor
            product_stats[product_key]["cveCount"] += 1
            if cve.get("severity") == "critical":
                product_stats[product_key]["criticalCount"] += 1
            if cve.get("severity") == "high":
                product_stats[product_key]["highCount"] += 1
            if cve.get("published") > product_stats[product_key]["lastCVE"]:
                product_stats[product_key]["lastCVE"] = cve.get("published", "")
    
    # Convert to lists and limit
    vendors = []
    for vendor, data in vendor_stats.items():
        vendors.append({
            "name": vendor,
            "productCount": len(data["products"]),
            "cveCount": data["cveCount"],
            "criticalCount": data["criticalCount"],
            "highCount": data["highCount"],
            "products": list(data["products"])[:5],
            "trending": random.choice(["up", "down", "stable"])
        })
    
    products = []
    for product_key, data in product_stats.items():
        products.append({
            "name": product_key.split(":")[1] if ":" in product_key else product_key,
            "vendor": data["vendor"],
            "cveCount": data["cveCount"],
            "criticalCount": data["criticalCount"],
            "highCount": data["highCount"],
            "lastCVE": data["lastCVE"]
        })
    
    vendors.sort(key=lambda x: x["cveCount"], reverse=True)
    products.sort(key=lambda x: x["cveCount"], reverse=True)
    
    return {
        "vendors": vendors[:200],  # Limit to top 200
        "products": products[:500],  # Limit to top 500
        "totalVendors": len(vendors),
        "totalProducts": len(products)
    }

# ============================================
# Statistics Endpoint
# ============================================

@app.get("/api/cve-statistics")
async def get_cve_statistics():
    """Get comprehensive CVE statistics (cached for performance)"""
    all_cves = cve_service.fetch_all_cves()
    
    # Yearly data (use all CVEs for accurate stats)
    yearly_map = defaultdict(int)
    cumulative = 0
    
    for cve in all_cves:
        year = cve.get("published", "").split("-")[0]
        if year and year.isdigit():
            yearly_map[int(year)] += 1
    
    yearly_data = []
    for year in sorted(yearly_map.keys()):
        cumulative += yearly_map[year]
        yearly_data.append({
            "year": year,
            "count": yearly_map[year],
            "cumulative": cumulative
        })
    
    # CVSS distribution (limit to 5000 for performance)
    cvss_map = defaultdict(int)
    for cve in all_cves[:5000]:
        score = int(cve.get("cvss_score", 0))
        if score > 0:
            cvss_map[score] += 1
    
    cvss_data = [{"score": s, "count": cvss_map[s]} for s in sorted(cvss_map.keys())]
    
    # Severity distribution
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for cve in all_cves:
        severity = cve.get("severity", "low")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # CWE distribution (limit to 2000 for performance)
    cwe_map = defaultdict(int)
    for cve in all_cves[:5000]:
        cwe = cve.get("cwe")
        if cwe:
            cwe_map[cwe] += 1
        else:
            desc = cve.get("description", "").lower()
            if "sql" in desc or "injection" in desc:
                cwe_map["CWE-89"] += 1
            elif "xss" in desc or "cross-site" in desc:
                cwe_map["CWE-79"] += 1
            else:
                cwe_map["CWE-20"] += 1
    
    cwe_data = [{"name": cwe, "count": count} for cwe, count in sorted(cwe_map.items(), key=lambda x: x[1], reverse=True)[:20]]
    
    # Recent activity
    now = datetime.now()
    last_24h = 0
    last_7d = 0
    last_30d = 0
    last_90d = 0
    
    for cve in all_cves:
        pub_date_str = cve.get("published", "")
        if pub_date_str:
            try:
                pub_date = datetime.strptime(pub_date_str, "%Y-%m-%d")
                days_ago = (now - pub_date).days
                if days_ago <= 1:
                    last_24h += 1
                if days_ago <= 7:
                    last_7d += 1
                if days_ago <= 30:
                    last_30d += 1
                if days_ago <= 90:
                    last_90d += 1
            except:
                pass
    
    return {
        "yearly_data": yearly_data[-10:],  # Last 10 years
        "cvss_data": cvss_data,
        "severity_data": [
            {"name": "Critical", "value": severity_counts["critical"]},
            {"name": "High", "value": severity_counts["high"]},
            {"name": "Medium", "value": severity_counts["medium"]},
            {"name": "Low", "value": severity_counts["low"]}
        ],
        "cwe_data": cwe_data,
        "stats": {
            "total": len(all_cves),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "last_24h": last_24h,
            "last_7d": last_7d,
            "last_30d": last_30d,
            "last_90d": last_90d
        }
    }

    
@app.get("/api/actors")
async def get_actors(
    country: str = None,
    motivation: str = None
):
    """Get threat actor profiles"""
    actors_file = DATA_DIR / "real_actors.json"
    if actors_file.exists():
        with open(actors_file, 'r') as f:
            actors = json.load(f)
    else:
        actors = []
    
    if country:
        actors = [a for a in actors if a.get("country") == country]
    if motivation:
        actors = [a for a in actors if motivation in a.get("motivation", [])]
    
    return actors

@app.get("/api/actors/{actor_id}")
async def get_actor(actor_id: str):
    """Get specific threat actor"""
    actors_file = DATA_DIR / "real_actors.json"
    if actors_file.exists():
        with open(actors_file, 'r') as f:
            actors = json.load(f)
            for actor in actors:
                if actor.get("id") == actor_id:
                    return actor
    return {"error": "Actor not found"}, 404

@app.get("/api/attack-trends")
async def get_attack_trends():
    """Get attack trend data"""
    from datetime import datetime
    now = datetime.now()
    trends = []
    
    for i in range(24):
        hour = (now.hour - i) % 24
        base_attacks = 50 + (hour * 3)
        trends.append({
            "hour": f"{hour:02d}:00",
            "attacks": base_attacks + (i * 5) % 30,
            "malware": int(base_attacks * 0.3),
            "phishing": int(base_attacks * 0.25),
            "ddos": int(base_attacks * 0.15)
        })
    
    return list(reversed(trends))

@app.get("/api/country-attacks")
async def get_country_attacks():
    """Get attack source countries"""
    return threat_aggregator.get_country_stats()

@app.post("/api/reports/generate")
async def generate_report(request: dict, authorization: str = Header(None)):
    """Generate threat intelligence report"""
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    report_type = request.get("type", "executive")
    date_range = request.get("date_range", "7d")
    filters = request.get("filters", {})
    format_type = request.get("format", "pdf")
    
    stats = threat_aggregator.get_dashboard_stats()
    alerts = threat_aggregator.get_recent_alerts()[:1000]  # Limit to 1000 for reports
    
    report = {
        "id": f"REP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "type": report_type,
        "date_range": date_range,
        "format": format_type,
        "generated_at": datetime.now().isoformat(),
        "generated_by": user["email"],
        "stats": stats,
        "alerts_count": len(alerts),
        "filters": filters,
        "status": "generated",
        "download_url": f"/api/reports/download/REP-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    }
    
    reports_file = DATA_DIR / "reports.json"
    reports = []
    if reports_file.exists():
        with open(reports_file, 'r') as f:
            reports = json.load(f)
    
    reports.append(report)
    
    with open(reports_file, 'w') as f:
        json.dump(reports, f, indent=2)
    
    return report

@app.get("/api/reports")
async def get_reports(authorization: str = Header(None)):
    """Get all generated reports"""
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    reports_file = DATA_DIR / "reports.json"
    reports = []
    if reports_file.exists():
        with open(reports_file, 'r') as f:
            reports = json.load(f)
    
    return reports

@app.get("/api/reports/download/{report_id}")
async def download_report(report_id: str, format: str = "pdf", authorization: str = Header(None)):
    """Download a generated report"""
    logger.info(f"=== Downloading report {report_id} in format {format} ===")
    
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        reports_file = DATA_DIR / "reports.json"
        report = None
        if reports_file.exists():
            with open(reports_file, 'r') as f:
                reports = json.load(f)
                for r in reports:
                    if r.get("id") == report_id:
                        report = r
                        break
        
        if not report:
            return JSONResponse(status_code=404, content={"error": "Report not found"})
        
        stats = threat_aggregator.get_dashboard_stats()
        alerts = threat_aggregator.get_recent_alerts()[:1000]
        
        try:
            cves = cve_service.fetch_all_cves()
        except Exception as e:
            logger.error(f"Error fetching CVEs: {e}")
            cves = []
        
        report_data = {
            "report_id": report_id,
            "generated_at": report.get("generated_at"),
            "generated_by": report.get("generated_by"),
            "stats": stats,
            "alerts": alerts,
            "cves": cves[:500],  # Limit to 500 CVEs
            "iocs": threat_aggregator.get_all_iocs()
        }
        
        format_lower = format.lower()
        logger.info(f"Generating report in format: {format_lower}")
        
        if format_lower == "pdf":
            content = report_service.generate_pdf(report_data, report.get("type", "executive"))
            media_type = "application/pdf"
            filename = f"report_{report_id}.pdf"
        elif format_lower == "csv":
            content = report_service.generate_csv(report_data, report.get("type", "executive"))
            media_type = "text/csv"
            filename = f"report_{report_id}.csv"
        else:
            content = report_service.generate_json(report_data)
            media_type = "application/json"
            filename = f"report_{report_id}.json"
        
        logger.info(f"Content size: {len(content) if isinstance(content, bytes) else len(content.encode())} bytes")
        
        return Response(
            content=content if isinstance(content, bytes) else content.encode('utf-8'),
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})



# ============================================
# Real-Time API Integration Endpoints
# ============================================

@app.post("/api/virustotal/scan-ip")
async def scan_ip_virustotal(request: VirusTotalRequest):
    """Scan IP address on VirusTotal"""
    if not request.ip:
        return {"error": "IP address is required"}, 400
    
    result = vt_service.check_ip(request.ip)
    return result

@app.post("/api/virustotal/scan-domain")
async def scan_domain_virustotal(request: VirusTotalRequest):
    """Scan domain on VirusTotal"""
    if not request.domain:
        return {"error": "Domain is required"}, 400
    
    result = vt_service.check_domain(request.domain)
    return result

@app.post("/api/virustotal/scan-url")
async def scan_url_virustotal(request: VirusTotalRequest):
    """Scan URL on VirusTotal"""
    if not request.url:
        return {"error": "URL is required"}, 400
    
    result = vt_service.submit_url(request.url)
    return result

@app.post("/api/virustotal/check-hash")
async def check_hash_virustotal(request: VirusTotalRequest):
    """Check file hash on VirusTotal"""
    if not request.file_hash:
        return {"error": "File hash is required"}, 400
    
    result = vt_service.check_file(request.file_hash)
    return result

@app.post("/api/abuseipdb/check-ip")
async def check_ip_abuseipdb(request: AbuseIPDBRequest):
    """Check IP on AbuseIPDB"""
    result = abuseipdb_service.check_ip(request.ip, request.max_age_days)
    return result

@app.post("/api/scan")
async def combined_scan(request: ScanRequest):
    """Combined scan using multiple threat intelligence sources"""
    query = request.query
    results = {
        "query": query,
        "timestamp": datetime.now().isoformat(),
        "sources": {}
    }
    
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$'
    url_pattern = r'^https?://'
    hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
    
    if re.match(ip_pattern, query):
        results["type"] = "ip"
        results["sources"]["virustotal"] = vt_service.check_ip(query)
        results["sources"]["abuseipdb"] = abuseipdb_service.check_ip(query)
    elif re.match(domain_pattern, query):
        results["type"] = "domain"
        results["sources"]["virustotal"] = vt_service.check_domain(query)
    elif re.match(url_pattern, query):
        results["type"] = "url"
        results["sources"]["virustotal"] = vt_service.submit_url(query)
    elif re.match(hash_pattern, query):
        results["type"] = "hash"
        results["sources"]["virustotal"] = vt_service.check_file(query)
    else:
        results["type"] = "unknown"
        results["sources"]["virustotal"] = vt_service.check_domain(query)
    
    vt_result = results["sources"].get("virustotal", {})
    abuse_result = results["sources"].get("abuseipdb", {})
    
    threat_score = 0
    if vt_result.get("success"):
        stats = vt_result.get("stats", {})
        malicious = stats.get("malicious", 0)
        total = stats.get("total", 1)
        threat_score += (malicious / total) * 100 if total > 0 else 0
    
    if abuse_result.get("success"):
        confidence = abuse_result.get("abuse_confidence_score", 0)
        threat_score = max(threat_score, confidence)
    
    results["threat_score"] = min(100, int(threat_score))
    
    if threat_score >= 75:
        results["threat_level"] = "critical"
    elif threat_score >= 50:
        results["threat_level"] = "high"
    elif threat_score >= 25:
        results["threat_level"] = "medium"
    elif threat_score > 0:
        results["threat_level"] = "low"
    else:
        results["threat_level"] = "safe"
    
    return results

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    stats = threat_aggregator.get_dashboard_stats()
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "data_sources": {
            "urlhaus": "connected",
            "emerging_threats": "connected",
            "openphish": "connected",
            "virustotal": "connected",
            "abuseipdb": "connected"
        },
        "stats": stats
    }

@app.post("/api/refresh")
async def refresh_threat_data():
    """Manually refresh threat data from all sources"""
    try:
        data = threat_aggregator.get_all_iocs(force_refresh=True)
        total = len(data.get("urls", [])) + len(data.get("ips", [])) + len(data.get("domains", []))
        
        return {
            "success": True,
            "message": "Threat data refreshed successfully",
            "total_iocs": total,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@app.get("/api/sources/status")
async def get_source_status():
    """Get status of all threat intelligence sources"""
    return {
        "sources": [
            {"name": "URLhaus", "status": "connected", "type": "malware_urls"},
            {"name": "Emerging Threats", "status": "connected", "type": "malicious_ips"},
            {"name": "OpenPhish", "status": "connected", "type": "phishing_urls"},
            {"name": "VirusTotal", "status": "connected", "type": "reputation"},
            {"name": "AbuseIPDB", "status": "connected", "type": "ip_reputation"},
            {"name": "FireHOL", "status": "connected", "type": "malicious_ips"},
            {"name": "Blocklist.de", "status": "connected", "type": "malicious_ips"},
            {"name": "AlienVault OTX", "status": "connected", "type": "malicious_ips"},
            {"name": "CISA Known Exploited", "status": "connected", "type": "known_vulnerabilities"}
        ],
        "last_update": datetime.now().isoformat()
    }

# ============================================
# WebSocket for Real-Time Updates
# ============================================

# Store active WebSocket connections
active_connections = set()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time threat updates"""
    await websocket.accept()
    active_connections.add(websocket)
    logger.info(f"✅ New WebSocket connection. Total: {len(active_connections)}")
    
    try:
        stats = threat_aggregator.get_dashboard_stats()
        await websocket.send_json({
            "type": "initial",
            "data": stats,
            "timestamp": datetime.now().isoformat()
        })
        
        while True:
            # Set a timeout to keep the connection alive
            data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            if data == "ping":
                await websocket.send_text("pong")
            elif data == "get_stats":
                stats = threat_aggregator.get_dashboard_stats()
                await websocket.send_json({
                    "type": "stats_update",
                    "data": stats,
                    "timestamp": datetime.now().isoformat()
                })
    except asyncio.TimeoutError:
        # Send a keepalive ping
        try:
            await websocket.send_text("ping")
        except:
            pass
    except WebSocketDisconnect:
        active_connections.discard(websocket)
        logger.info(f"❌ WebSocket disconnected. Total: {len(active_connections)}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        active_connections.discard(websocket)
    finally:
        active_connections.discard(websocket)

async def broadcast_threat_updates():
    """Background task that periodically checks for new threats and broadcasts updates"""
    last_count = 0
    last_alerts = []
    
    while True:
        try:
            # Get current stats
            stats = threat_aggregator.get_dashboard_stats()
            current_count = stats.get("active_threats", 0)
            
            # Broadcast stats if changed
            if current_count != last_count:
                await websocket_manager.send_stats_update(stats)
                last_count = current_count
            
            # Get recent alerts and broadcast new ones (limit to 20 for performance)
            alerts = threat_aggregator.get_recent_alerts()[:100]
            if alerts:
                for alert in alerts[:10]:
                    alert_id = alert.get("id", "")
                    if alert_id and alert_id not in last_alerts:
                        await websocket_manager.send_threat_update(alert)
                        last_alerts.append(alert_id)
                        if len(last_alerts) > 10:
                            last_alerts.pop(0)
            
        except Exception as e:
            logger.error(f"WebSocket broadcast error: {e}")
        
        await asyncio.sleep(10)


# ============================================
# Authentication Models & Routes (unchanged)
# ============================================

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

class VerifyEmailRequest(BaseModel):
    email: EmailStr
    otp: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    remember_me: bool = False

class PasswordResetRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

class UpdateProfileRequest(BaseModel):
    username: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

@app.post("/api/auth/register")
async def register(request: RegisterRequest):
    try:
        result = auth_service.register_user(
            email=request.email,
            username=request.username,
            password=request.password
        )
        return JSONResponse(status_code=201, content=result)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/auth/verify-email")
async def verify_email(request: VerifyEmailRequest):
    try:
        result = auth_service.verify_email(
            email=request.email,
            otp=request.otp
        )
        return result
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/auth/login")
async def login(request: LoginRequest):
    try:
        result = auth_service.login(
            email=request.email,
            password=request.password,
            remember_me=request.remember_me
        )
        return result
    except ValueError as e:
        return JSONResponse(status_code=401, content={"error": str(e)})

@app.post("/api/auth/request-password-reset")
async def request_password_reset(request: PasswordResetRequest):
    try:
        result = auth_service.request_password_reset(email=request.email)
        return result
    except ValueError as e:
        return JSONResponse(status_code=404, content={"error": str(e)})

@app.post("/api/auth/reset-password")
async def reset_password(request: ResetPasswordRequest):
    try:
        result = auth_service.reset_password(
            email=request.email,
            otp=request.otp,
            new_password=request.new_password
        )
        return result
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/auth/resend-verification")
async def resend_verification(request: PasswordResetRequest):
    try:
        from services.otp_service import otp_service
        user = auth_service.get_user_by_email(request.email)
        if not user:
            return JSONResponse(status_code=404, content={"error": "User not found"})
        
        is_verified = user.get("is_verified") if isinstance(user, dict) else user.is_verified
        if is_verified:
            return JSONResponse(status_code=400, content={"error": "Email already verified"})
        
        otp = otp_service.generate_otp(request.email, "verification")
        otp_service.send_verification_email(request.email, otp)
        
        return {"message": "Verification OTP sent to your email"}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.put("/api/auth/update-profile")
async def update_profile(authorization: str = None, request: UpdateProfileRequest = None):
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        result = auth_service.update_profile(user["email"], request.username)
        return result
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/auth/change-password")
async def change_password(authorization: str = None, request: ChangePasswordRequest = None):
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        result = auth_service.change_password(
            email=user["email"],
            current_password=request.current_password,
            new_password=request.new_password
        )
        return result
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.get("/api/auth/me")
async def get_current_user(authorization: str = Header(None)):
    logger.info("=== /api/auth/me called ===")
    
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    return user

async def get_current_user_from_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user

# ============================================
# Alerts Endpoints
# ============================================

class CVEAlerRequest(BaseModel):
    cve_id: str
    severity: str

@app.post("/api/alerts/cve")
async def create_cve_alert(request: CVEAlerRequest, authorization: str = Header(None)):
    logger.info(f"=== Creating alert for CVE: {request.cve_id} ===")
    
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        DATA_DIR.mkdir(exist_ok=True)
        
        alerts_file = DATA_DIR / "alerts.json"
        alerts = []
        if alerts_file.exists():
            with open(alerts_file, 'r') as f:
                alerts = json.load(f)
        
        existing = [a for a in alerts if a.get("cve_id") == request.cve_id and a.get("user_email") == user["email"]]
        if existing:
            return JSONResponse(status_code=400, content={"error": "Alert already exists for this CVE"})
        
        new_alert = {
            "id": f"alert_{len(alerts) + 1}_{int(datetime.now().timestamp())}",
            "cve_id": request.cve_id,
            "severity": request.severity,
            "user_email": user["email"],
            "user_name": user["username"],
            "created_at": datetime.now().isoformat(),
            "status": "active"
        }
        
        alerts.append(new_alert)
        
        with open(alerts_file, 'w') as f:
            json.dump(alerts, f, indent=2)
        
        return {"success": True, "message": f"Alert created for {request.cve_id}", "alert": new_alert}
        
    except Exception as e:
        logger.error(f"Error creating alert: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/alerts")
async def get_user_alerts(authorization: str = Header(None)):
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    alerts_file = DATA_DIR / "alerts.json"
    alerts = []
    if alerts_file.exists():
        with open(alerts_file, 'r') as f:
            all_alerts = json.load(f)
            alerts = [a for a in all_alerts if a.get("user_email") == user["email"]]
    
    return alerts

@app.delete("/api/alerts/{alert_id}")
async def delete_alert(alert_id: str, authorization: str = Header(None)):
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        alerts_file = DATA_DIR / "alerts.json"
        alerts = []
        if alerts_file.exists():
            with open(alerts_file, 'r') as f:
                alerts = json.load(f)
        
        alerts = [a for a in alerts if not (a.get("id") == alert_id and a.get("user_email") == user["email"])]
        
        with open(alerts_file, 'w') as f:
            json.dump(alerts, f, indent=2)
        
        return {"success": True, "message": "Alert deleted successfully"}
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ============================================
# Settings Endpoints
# ============================================

@app.get("/api/settings")
async def get_settings(authorization: str = Header(None)):
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    settings_file = DATA_DIR / "settings.json"
    settings = {}
    if settings_file.exists():
        with open(settings_file, 'r') as f:
            all_settings = json.load(f)
            settings = all_settings.get(user["email"], {})
    
    default_settings = {
        "settings": {
            "orgName": "Nepal Bankers Association",
            "tier": "Tier 2 - Enterprise",
            "contactEmail": user["email"],
            "timezone": "Asia/Kathmandu",
            "sessionTimeout": "30",
            "ipWhitelist": "202.166.192.0/24\n202.166.196.0/24",
            "twoFactorEnabled": False
        },
        "notifications": [
            {"id": "critical", "label": "Critical Threat Alerts", "desc": "Receive immediate alerts for critical threats", "enabled": True},
            {"id": "daily", "label": "Daily Summary", "desc": "Daily email summary of threat activity", "enabled": True},
            {"id": "weekly", "label": "Weekly Reports", "desc": "Automated weekly intelligence reports", "enabled": False},
            {"id": "cve", "label": "CVE Updates", "desc": "Notifications for new critical/high CVEs", "enabled": True},
            {"id": "ioc", "label": "IOC Updates", "desc": "Alerts for new IOCs targeting Nepal", "enabled": True}
        ],
        "apiKeys": {
            "virustotal": "",
            "alienvault": "",
            "abuseipdb": ""
        }
    }
    
    result = default_settings.copy()
    if settings:
        result.update(settings)
    
    return result

@app.put("/api/settings")
async def update_settings(request: dict, authorization: str = Header(None)):
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        settings_file = DATA_DIR / "settings.json"
        all_settings = {}
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                all_settings = json.load(f)
        
        all_settings[user["email"]] = {
            "settings": request.get("settings", {}),
            "notifications": request.get("notifications", []),
            "apiKeys": request.get("apiKeys", {})
        }
        
        with open(settings_file, 'w') as f:
            json.dump(all_settings, f, indent=2)
        
        return {"success": True, "message": "Settings saved successfully"}
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.put("/api/settings/api-keys")
async def update_api_keys(request: dict, authorization: str = Header(None)):
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        settings_file = DATA_DIR / "settings.json"
        all_settings = {}
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                all_settings = json.load(f)
        
        user_settings = all_settings.get(user["email"], {})
        user_api_keys = user_settings.get("apiKeys", {})
        
        for key, value in request.items():
            user_api_keys[key] = value
        
        user_settings["apiKeys"] = user_api_keys
        all_settings[user["email"]] = user_settings
        
        with open(settings_file, 'w') as f:
            json.dump(all_settings, f, indent=2)
        
        return {"success": True, "message": "API keys updated successfully"}
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.put("/api/settings/two-factor")
async def update_two_factor(request: dict, authorization: str = Header(None)):
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JSONResponse(status_code=401, content={"error": "Invalid authorization header"})
    
    token = parts[1]
    user = auth_service.get_current_user(token)
    
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})
    
    try:
        settings_file = DATA_DIR / "settings.json"
        all_settings = {}
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                all_settings = json.load(f)
        
        user_settings = all_settings.get(user["email"], {})
        user_settings["settings"] = user_settings.get("settings", {})
        user_settings["settings"]["twoFactorEnabled"] = request.get("enabled", False)
        
        all_settings[user["email"]] = user_settings
        
        with open(settings_file, 'w') as f:
            json.dump(all_settings, f, indent=2)
        
        return {"success": True, "message": "Two-factor authentication updated"}
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# ============================================
# File Upload & Scanning Endpoint
# ============================================

class FileScanResponse(BaseModel):
    success: bool
    filename: str
    file_size: int
    file_hashes: Dict[str, str]
    threat_score: int
    threat_level: str
    scan_results: Dict[str, Any]
    timestamp: str

@app.post("/api/scan-file")
async def scan_file(
    file: UploadFile = File(...),
    authorization: str = Header(None)
):
    """
    Upload and scan a file for malware using multiple threat intelligence platforms
    """
    logger.info(f"📁 File upload received: {file.filename}")
    
    # Validate file size (limit to 100MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    file_size = 0
    
    try:
        # Read file content
        content = await file.read()
        file_size = len(content)
        
        if file_size > MAX_FILE_SIZE:
            return JSONResponse(
                status_code=400,
                content={"error": f"File too large. Max size: {MAX_FILE_SIZE // (1024*1024)}MB"}
            )
        
        # Calculate file hashes
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        md5_hash.update(content)
        sha1_hash.update(content)
        sha256_hash.update(content)
        
        file_hashes = {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
        
        logger.info(f"📊 File hashes: {file_hashes}")
        
        # Scan with VirusTotal (file hash)
        vt_result = vt_service.check_file(file_hashes["sha256"])
        
        # Calculate threat score from VirusTotal
        threat_score = 0
        if vt_result.get("success") and vt_result.get("stats"):
            malicious = vt_result["stats"].get("malicious", 0)
            total = vt_result["stats"].get("total", 1)
            threat_score = int((malicious / total) * 100)
        
        # Determine threat level
        if threat_score >= 75:
            threat_level = "critical"
        elif threat_score >= 50:
            threat_level = "high"
        elif threat_score >= 25:
            threat_level = "medium"
        elif threat_score > 0:
            threat_level = "low"
        else:
            threat_level = "safe"
        
        return {
            "success": True,
            "filename": file.filename,
            "file_size": file_size,
            "file_hashes": file_hashes,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "scan_results": {
                "virustotal": vt_result
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error scanning file: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Scan failed: {str(e)}"}
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)