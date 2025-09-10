from flask import Flask, render_template, request, send_file, jsonify
import requests
import csv
import os
import json
from datetime import datetime
import certifi

app = Flask(__name__)

# API Keys (read from environment variables)
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", "")
IPGEOLOCATION_API_KEY = os.getenv("IPGEOLOCATION_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# SSL verification configuration
# Set VERIFY_SSL=false to bypass verification (not recommended for production)
# Or set REQUESTS_CA_BUNDLE/SSL_CERT_FILE to a custom CA bundle path
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"
CUSTOM_CA_BUNDLE = os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("SSL_CERT_FILE")

def _verify_param():
    if not VERIFY_SSL:
        return False
    if CUSTOM_CA_BUNDLE and os.path.exists(CUSTOM_CA_BUNDLE):
        return CUSTOM_CA_BUNDLE
    # Fall back to certifi bundle
    return certifi.where()

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    search_result = None

    if request.method == "POST":
        ioc = request.form.get("ioc")
        tag = request.form.get("tag", "").strip()
        export = request.form.get("export")

        if ioc:
            result = check_virustotal(ioc)

            result["tag"] = tag if tag else "None"

            # Save to CSV if export is selected
            if export:
                file_exists = os.path.exists("threat_data.csv")
                with open("threat_data.csv", "a", newline="") as f:
                    writer = csv.writer(f)
                    if not file_exists:
                        writer.writerow(["IOC", "Malicious", "Suspicious", "Harmless", "Abuse Score", "Abuse Categories", "Tag"])
                    writer.writerow([
                        result["ioc"],
                        result["malicious"],
                        result["suspicious"],
                        result["harmless"],
                        result["abuse_score"],
                        result["abuse_category"],
                        result["tag"]
                    ])

    return render_template("index.html", result=result, search_result=search_result)

def get_ip_geolocation(ip):
    """Get IP geolocation information"""
    if not IPGEOLOCATION_API_KEY:
        return None
    
    try:
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={IPGEOLOCATION_API_KEY}&ip={ip}"
        verify = _verify_param()
        response = requests.get(url, timeout=10, verify=verify)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Geolocation API error: {e}")
    return None

def get_shodan_info(ip):
    """Get Shodan information for IP"""
    if not SHODAN_API_KEY:
        return None
    
    try:
        headers = {"X-API-Key": SHODAN_API_KEY}
        url = f"https://api.shodan.io/shodan/host/{ip}"
        verify = _verify_param()
        response = requests.get(url, headers=headers, timeout=10, verify=verify)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Shodan API error: {e}")
    return None

def check_virustotal(ioc):
    headers = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}
    is_ip = ioc.replace(".", "").isdigit()

    if is_ip:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"

    verify = _verify_param()
    vt_response = requests.get(url, headers=headers, verify=verify, timeout=15) if headers else None

    result = {
        "ioc": ioc,
        "malicious": "N/A",
        "suspicious": "N/A",
        "harmless": "N/A",
        "abuse_score": "N/A",
        "abuse_category": "N/A",
        "geolocation": None,
        "shodan_info": None,
        "threat_level": "Unknown",
        "last_seen": "N/A",
        "asn": "N/A",
        "organization": "N/A"
    }

    if vt_response is not None and vt_response.status_code == 200:
        data = vt_response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        result["malicious"] = stats.get("malicious", "N/A")
        result["suspicious"] = stats.get("suspicious", "N/A")
        result["harmless"] = stats.get("harmless", "N/A")
        
        # Determine threat level
        malicious_count = int(result["malicious"]) if result["malicious"] != "N/A" else 0
        suspicious_count = int(result["suspicious"]) if result["suspicious"] != "N/A" else 0
        
        if malicious_count >= 5:
            result["threat_level"] = "High"
        elif malicious_count >= 2 or suspicious_count >= 3:
            result["threat_level"] = "Medium"
        elif malicious_count >= 1 or suspicious_count >= 1:
            result["threat_level"] = "Low"
        else:
            result["threat_level"] = "Clean"

    if is_ip and ABUSE_API_KEY:
        abuse_headers = {
            "Key": ABUSE_API_KEY,
            "Accept": "application/json"
        }
        abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}&maxAgeInDays=90"
        abuse_response = requests.get(abuse_url, headers=abuse_headers, verify=verify, timeout=15)
        if abuse_response.status_code == 200:
            abuse_data = abuse_response.json().get("data", {})
            result["abuse_score"] = abuse_data.get("abuseConfidenceScore", "N/A")
            result["abuse_category"] = ", ".join(str(cat) for cat in abuse_data.get("category", []))

    # Get geolocation for IP addresses
    if is_ip:
        result["geolocation"] = get_ip_geolocation(ioc)
        result["shodan_info"] = get_shodan_info(ioc)
        
        if result["geolocation"]:
            result["asn"] = result["geolocation"].get("asn", "N/A")
            result["organization"] = result["geolocation"].get("organization", "N/A")

    return result

@app.route("/search", methods=["POST"])
def search():
    search_ioc = request.form.get("search_ioc")
    search_result = "No matching record found."

    if os.path.exists("threat_data.csv"):
        with open("threat_data.csv", "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["IOC"] == search_ioc:
                    search_result = row
                    break

    return render_template("index.html", result=None, search_result=search_result)

@app.route("/download")
def download_csv():
    csv_path = os.path.join(os.path.dirname(__file__), "threat_data.csv")
    return send_file(csv_path, as_attachment=True)

@app.route("/api/geolocation/<ip>")
def api_geolocation(ip):
    """API endpoint for geolocation data"""
    geolocation = get_ip_geolocation(ip)
    if geolocation:
        return jsonify(geolocation)
    return jsonify({"error": "Geolocation data not available"}), 404

if __name__ == "__main__":
    app.run(debug=True)
