import requests
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_KEY = os.getenv("SHODAN_API_KEY")

def analyze_ip(ip):
    """IP adresini tüm kaynaklarla analiz et"""
    results = {
        "ip": ip,
        "virustotal": {},
        "abuseipdb": {},
        "shodan": {},
        "threat_score": 0,
        "threat_level": "LOW",
        "threat_tags": [],
        "summary": {}
    }

    # VirusTotal
    vt = _check_virustotal_ip(ip)
    results["virustotal"] = vt
    if vt.get("malicious", 0) > 0:
        results["threat_score"] += vt["malicious"] * 3
        results["threat_tags"].append(f"VT:{vt['malicious']} engines")

    # AbuseIPDB
    abuse = _check_abuseipdb(ip)
    results["abuseipdb"] = abuse
    score = abuse.get("abuse_score", 0)
    if score > 0:
        results["threat_score"] += score // 2
        results["threat_tags"].append(f"Abuse:{score}%")
    if abuse.get("is_tor"):
        results["threat_score"] += 30
        results["threat_tags"].append("TOR")
    if abuse.get("is_vpn"):
        results["threat_score"] += 20
        results["threat_tags"].append("VPN")

    # Shodan
    shodan = _check_shodan(ip)
    results["shodan"] = shodan
    if shodan.get("open_ports"):
        results["threat_tags"].append(f"Ports:{len(shodan['open_ports'])}")

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
        "ip": ip,
        "threat_score": results["threat_score"],
        "threat_level": results["threat_level"],
        "tags": results["threat_tags"],
        "country": abuse.get("country", shodan.get("country", "Unknown")),
        "isp": abuse.get("isp", shodan.get("isp", "Unknown")),
        "malicious_engines": vt.get("malicious", 0),
        "abuse_reports": abuse.get("total_reports", 0),
        "open_ports": shodan.get("open_ports", [])
    }

    return results


def _check_virustotal_ip(ip):
    result = {"malicious": 0, "suspicious": 0, "harmless": 0, "error": None}
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers, timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["harmless"] = stats.get("harmless", 0)
            result["country"] = data["data"]["attributes"].get("country", "")
            result["as_owner"] = data["data"]["attributes"].get("as_owner", "")
        elif response.status_code == 404:
            result["error"] = "IP bulunamadı"
        else:
            result["error"] = f"API hatası: {response.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result


def _check_abuseipdb(ip):
    result = {
        "abuse_score": 0, "total_reports": 0,
        "country": "", "isp": "",
        "is_tor": False, "is_vpn": False,
        "error": None
    }
    try:
        headers = {
            "Key": ABUSEIPDB_KEY,
            "Accept": "application/json"
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params, timeout=10
        )
        if response.status_code == 200:
            data = response.json()["data"]
            result["abuse_score"] = data.get("abuseConfidenceScore", 0)
            result["total_reports"] = data.get("totalReports", 0)
            result["country"] = data.get("countryCode", "")
            result["isp"] = data.get("isp", "")
            result["is_tor"] = data.get("isTor", False)
            result["is_vpn"] = data.get("isPublic", False)
            result["usage_type"] = data.get("usageType", "")
        else:
            result["error"] = f"API hatası: {response.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result


def _check_shodan(ip):
    result = {
        "open_ports": [], "services": [],
        "country": "", "isp": "",
        "os": "", "error": None
    }
    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}",
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            result["open_ports"] = data.get("ports", [])
            result["country"] = data.get("country_name", "")
            result["isp"] = data.get("isp", "")
            result["os"] = data.get("os", "")
            result["hostnames"] = data.get("hostnames", [])
            result["services"] = [
                {"port": item.get("port"), "product": item.get("product", ""),
                 "version": item.get("version", "")}
                for item in data.get("data", [])
            ]
        elif response.status_code == 404:
            result["error"] = "Shodan'da kayıt yok"
        else:
            result["error"] = f"API hatası: {response.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result