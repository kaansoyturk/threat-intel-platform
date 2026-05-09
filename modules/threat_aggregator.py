from modules.ip_analyzer import analyze_ip
from modules.domain_analyzer import analyze_domain
from modules.cve_tracker import search_cves, get_recent_cves

def aggregate_threat(query, query_type="auto"):
    """Sorguyu otomatik algıla ve analiz et"""

    # Otomatik tip tespiti
    if query_type == "auto":
        import re
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, query):
            query_type = "ip"
        elif query.startswith("CVE-"):
            query_type = "cve"
        else:
            query_type = "domain"

    if query_type == "ip":
        return {"type": "ip", "data": analyze_ip(query)}
    elif query_type == "domain":
        return {"type": "domain", "data": analyze_domain(query)}
    elif query_type == "cve":
        return {"type": "cve", "data": search_cves(query)}
    else:
        return {"error": "Bilinmeyen sorgu tipi"}

def get_dashboard_data():
    """Dashboard için özet veri"""
    recent_cves = get_recent_cves(days=7, limit=10)
    return {
        "recent_cves": recent_cves,
        "stats": {
            "critical_cves": recent_cves.get("critical", 0),
            "high_cves": recent_cves.get("high", 0),
            "total_cves": recent_cves.get("total", 0)
        }
    }