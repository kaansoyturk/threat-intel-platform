import requests
import socket
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def analyze_domain(domain):
    """Domain'i analiz et"""
    results = {
        "domain": domain,
        "virustotal": {},
        "dns": {},
        "threat_score": 0,
        "threat_level": "LOW",
        "threat_tags": [],
        "summary": {}
    }

    # DNS çözümleme
    dns = _resolve_dns(domain)
    results["dns"] = dns

    # VirusTotal
    vt = _check_virustotal_domain(domain)
    results["virustotal"] = vt
    if vt.get("malicious", 0) > 0:
        results["threat_score"] += vt["malicious"] * 3
        results["threat_tags"].append(f"VT:{vt['malicious']} engines")

    if vt.get("categories"):
        for cat in vt["categories"].values():
            if any(bad in cat.lower() for bad in ["malware", "phishing", "spam", "botnet"]):
                results["threat_score"] += 20
                results["threat_tags"].append(f"Category:{cat}")

    # Threat level
    results["threat_score"] = min(100, results["threat_score"])
    if results["threat_score"] >= 70:
        results["threat_level"] = "CRITICAL"
    elif results["threat_score"] >= 40:
        results["threat_level"] = "HIGH"
    elif results["threat_score"] >= 20:
        results["threat_level"] = "MEDIUM"
    else:
        results["threat_level"] = "LOW"

    results["summary"] = {
        "domain": domain,
        "threat_score": results["threat_score"],
        "threat_level": results["threat_level"],
        "tags": results["threat_tags"],
        "ip": dns.get("ip", "Unknown"),
        "malicious_engines": vt.get("malicious", 0),
        "suspicious_engines": vt.get("suspicious", 0),
        "categories": list(vt.get("categories", {}).values())[:3]
    }

    return results


def _resolve_dns(domain):
    result = {"ip": "", "mx": [], "error": None}
    try:
        result["ip"] = socket.gethostbyname(domain)
    except Exception as e:
        result["error"] = str(e)
    return result


def _check_virustotal_domain(domain):
    result = {
        "malicious": 0, "suspicious": 0,
        "harmless": 0, "categories": {},
        "error": None
    }
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers, timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["harmless"] = stats.get("harmless", 0)
            result["categories"] = attrs.get("categories", {})
            result["reputation"] = attrs.get("reputation", 0)
            result["creation_date"] = attrs.get("creation_date", "")
        elif response.status_code == 404:
            result["error"] = "Domain bulunamadı"
        else:
            result["error"] = f"API hatası: {response.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result