import requests
from datetime import datetime, timedelta

def search_cves(keyword, limit=10):
    """CVE araması yap — NVD API kullan"""
    results = {
        "keyword": keyword,
        "cves": [],
        "total": 0,
        "critical": 0,
        "high": 0,
        "error": None
    }

    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": limit,
            "startIndex": 0
        }

        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            results["total"] = data.get("totalResults", 0)

            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                description = ""
                score = 0
                severity = "UNKNOWN"
                vector = ""

                # Açıklama
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")[:200]
                        break

                # CVSS Score
                metrics = cve.get("metrics", {})
                if metrics.get("cvssMetricV31"):
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]
                    score = cvss.get("baseScore", 0)
                    severity = cvss.get("baseSeverity", "UNKNOWN")
                    vector = cvss.get("vectorString", "")
                elif metrics.get("cvssMetricV30"):
                    cvss = metrics["cvssMetricV30"][0]["cvssData"]
                    score = cvss.get("baseScore", 0)
                    severity = cvss.get("baseSeverity", "UNKNOWN")
                elif metrics.get("cvssMetricV2"):
                    cvss = metrics["cvssMetricV2"][0]["cvssData"]
                    score = cvss.get("baseScore", 0)
                    severity = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"

                if severity == "CRITICAL":
                    results["critical"] += 1
                elif severity == "HIGH":
                    results["high"] += 1

                published = cve.get("published", "")[:10]
                modified = cve.get("lastModified", "")[:10]

                results["cves"].append({
                    "id": cve_id,
                    "description": description,
                    "score": score,
                    "severity": severity,
                    "vector": vector,
                    "published": published,
                    "modified": modified,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })

        else:
            results["error"] = f"NVD API hatası: {response.status_code}"

    except Exception as e:
        results["error"] = str(e)

    return results


def get_recent_cves(days=7, limit=20):
    """Son X gündeki CVE'leri getir"""
    results = {
        "cves": [],
        "total": 0,
        "critical": 0,
        "high": 0,
        "error": None
    }

    try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": limit,
            "cvssV3Severity": "CRITICAL"
        }

        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            results["total"] = data.get("totalResults", 0)

            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                description = ""
                score = 0
                severity = "UNKNOWN"

                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")[:200]
                        break

                metrics = cve.get("metrics", {})
                if metrics.get("cvssMetricV31"):
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]
                    score = cvss.get("baseScore", 0)
                    severity = cvss.get("baseSeverity", "UNKNOWN")

                if severity == "CRITICAL":
                    results["critical"] += 1
                elif severity == "HIGH":
                    results["high"] += 1

                results["cves"].append({
                    "id": cve_id,
                    "description": description,
                    "score": score,
                    "severity": severity,
                    "published": cve.get("published", "")[:10],
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })

        else:
            results["error"] = f"NVD API hatası: {response.status_code}"

    except Exception as e:
        results["error"] = str(e)

    return results