
# 🛡️ Cyber Threat Intelligence Dashboard

A modern, interactive Flask-based web dashboard that provides comprehensive threat intelligence analysis with **geolocation mapping**, **real-time threat assessment**, and **visual analytics**. The dashboard integrates multiple threat intelligence sources to deliver actionable cybersecurity insights.

## 🎯 Objective

To build an advanced threat intelligence dashboard that:

* Aggregates real-time threat data from multiple APIs
* Displays threat metrics with visual analytics and charts
* Provides geolocation mapping on an interactive world map
* Offers comprehensive IP reputation analysis
* Enables threat level assessment and risk categorization

## ⚙️ Features

### 🔍 **Threat Intelligence Sources**
* **VirusTotal** - Malicious, Suspicious, Harmless reports
* **AbuseIPDB** - Abuse confidence score and categories
* **IP Geolocation** - Geographic location and ISP information
* **Shodan** - Network and service information (optional)

### 🗺️ **Geographic Intelligence**
* **Interactive World Map** - Visual IP location mapping
* **Geolocation Data** - Country, city, region, ISP details
* **ASN Information** - Autonomous System Number and organization

### 📊 **Visual Analytics**
* **Threat Level Assessment** - High/Medium/Low/Clean classification
* **Interactive Charts** - Doughnut chart for threat breakdown
* **Real-time Dashboard** - Modern, responsive UI design

### 💾 **Data Management**
* Custom **tagging** for IOCs
* **Export to CSV** functionality
* **Search** previously saved IOCs
* **Download complete CSV report**

## 🧰 Tech Stack

| Layer     | Technology               |
| --------- | ------------------------ |
| Backend   | Python, Flask            |
| Frontend  | HTML5, CSS3, JavaScript  |
| Maps      | Leaflet.js               |
| Charts    | Chart.js                 |
| APIs Used | VirusTotal, AbuseIPDB, IPGeolocation, Shodan |
| Storage   | CSV File (exported IOCs) |

---

## 🚀 How to Run Locally

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/cyber-threat-intel-dashboard.git
cd cyber-threat-intel-dashboard
```

### 2. Create Virtual Environment

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/Mac
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Environment Variables

Create a `.env` file or set environment variables:

```bash
# Windows PowerShell
$env:VT_API_KEY="your_virustotal_api_key"
$env:ABUSE_API_KEY="your_abuseipdb_api_key"
$env:IPGEOLOCATION_API_KEY="your_ipgeolocation_api_key"
$env:SHODAN_API_KEY="your_shodan_api_key"

# Linux/Mac
export VT_API_KEY="your_virustotal_api_key"
export ABUSE_API_KEY="your_abuseipdb_api_key"
export IPGEOLOCATION_API_KEY="your_ipgeolocation_api_key"
export SHODAN_API_KEY="your_shodan_api_key"
```

### 5. Run the App

```bash
python app.py
```

Visit the app at: [http://127.0.0.1:5000](http://127.0.0.1:5000)

## 🔑 API Keys Required

| Service | Purpose | Free Tier | Get Key |
|---------|---------|-----------|---------|
| **VirusTotal** | Threat intelligence | ✅ Yes | [Sign up](https://www.virustotal.com/) |
| **AbuseIPDB** | IP reputation | ✅ Yes | [Sign up](https://abuseipdb.com/) |
| **IP Geolocation** | Geographic data | ✅ Yes | [Sign up](https://ipgeolocation.io/) |
| **Shodan** | Network intelligence | ⚠️ Limited | [Sign up](https://shodan.io/) |

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

