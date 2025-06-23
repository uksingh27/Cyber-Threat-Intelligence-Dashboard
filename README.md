
# 🛡️ Cyber Threat Intelligence Dashboard

A Flask-based web dashboard that enables real-time lookup of IP addresses and domains using **VirusTotal** and **AbuseIPDB** APIs. It provides threat analysis, tagging, export functionality, and IOC history search—making it a lightweight but effective tool for cybersecurity analysts.

## 🎯 Objective

To build a threat intelligence dashboard that:

* Aggregates real-time threat data from public APIs.
* Displays threat metrics and IOC risk assessments.
* Allows users to tag, export, and search IOCs.

## ⚙️ Features

✅ Lookup for IPs/domains using:

* **VirusTotal** (Malicious, Suspicious, Harmless reports)
* **AbuseIPDB** (Abuse score, categories)

✅ Additional capabilities:

* Custom **tagging** for IOCs
* **Export to CSV**
* **Search** previously saved IOCs
* **Download complete CSV report**

## 🧰 Tech Stack

| Layer     | Technology               |
| --------- | ------------------------ |
| Backend   | Python, Flask            |
| Frontend  | HTML (Jinja2)            |
| APIs Used | VirusTotal, AbuseIPDB    |
| Storage   | CSV File (exported IOCs) |

---

## 🚀 How to Run Locally

### 1. Clone the Repository

git clone https://github.com/your-username/cyber-threat-intel-dashboard.git
cd cyber-threat-intel-dashboard

### 2. Install Dependencies

pip install flask requests

### 3. Add Your API Keys

In `app.py`, replace:

VT_API_KEY = "your_virustotal_api_key"
ABUSE_API_KEY = "your_abuseipdb_api_key"


🔐 *You can obtain free API keys from [VirusTotal](https://www.virustotal.com/) and [AbuseIPDB](https://abuseipdb.com/).*

### 4. Run the App

python app.py

Visit the app at: [http://127.0.0.1:5000](http://127.0.0.1:5000)

## 💡 Example Use Cases

* Analyze suspicious IP addresses or domains from logs.
* Tag IOCs related to specific campaigns or alerts.
* Export findings for incident response reports.
* Maintain a lightweight IOC tracking database in CSV format.

---

## 📌 Future Improvements

* Add MongoDB/SQLite for persistent storage.
* Visualization charts (IOC volume over time).
* API rate limiting and error handling.
* User **authentication** for multi-user use.

👤 Author

Suhaila P.S
Cybersecurity Analyst

