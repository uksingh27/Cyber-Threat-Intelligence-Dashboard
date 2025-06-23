from flask import Flask, render_template, request, send_file
import requests
import csv
import os

app = Flask(__name__)

# VirusTotal and AbuseIPDB API Keys
VT_API_KEY = "YOUR_VIRUSTOTAL_KEY"
ABUSE_API_KEY = "YOUR_ABUSEIPDB_KEY"
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

def check_virustotal(ioc):
    headers = {"x-apikey": VT_API_KEY}
    is_ip = ioc.replace(".", "").isdigit()

    if is_ip:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"

    vt_response = requests.get(url, headers=headers)

    result = {
        "ioc": ioc,
        "malicious": "N/A",
        "suspicious": "N/A",
        "harmless": "N/A",
        "abuse_score": "N/A",
        "abuse_category": "N/A"
    }

    if vt_response.status_code == 200:
        data = vt_response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        result["malicious"] = stats.get("malicious", "N/A")
        result["suspicious"] = stats.get("suspicious", "N/A")
        result["harmless"] = stats.get("harmless", "N/A")

    if is_ip:
        abuse_headers = {
            "Key": ABUSE_API_KEY,
            "Accept": "application/json"
        }
        abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}&maxAgeInDays=90"
        abuse_response = requests.get(abuse_url, headers=abuse_headers)
        if abuse_response.status_code == 200:
            abuse_data = abuse_response.json().get("data", {})
            result["abuse_score"] = abuse_data.get("abuseConfidenceScore", "N/A")
            result["abuse_category"] = ", ".join(str(cat) for cat in abuse_data.get("category", []))

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

if __name__ == "__main__":
    app.run(debug=True)
