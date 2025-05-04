# 🛡️ 3DS Checkout Analysis & Risk Scoring System

This project is a fully automated web reconnaissance and risk analysis platform that simulates **checkout flows on e-commerce sites** to detect **3D Secure (3DS)** implementation and assess infrastructure risk.

Built with **Scrapy**, **Playwright**, and **Shodan**, it provides actionable intelligence via both CLI and API.

---

## 🚀 Features

### ✅ 1. Dynamic Checkout Simulation (Playwright)

* Full browser automation
* Add-to-cart, checkout, and form submission flows
* Detects **3DS** popups (iframe or redirect) **only visible after interaction**
* Measures behavioral timing and redirection patterns

### ✅ 2. Platform-Aware Checkout Automation

* Detects Shopify, WooCommerce, Magento, etc.
* Auto-navigates products → cart → payment form
* Fills test card and address data (Visa 4111 test numbers)

### ✅ 3. Infrastructure Enrichment

For each domain, we gather:

* 🔍 **Domain/IP resolution**
* 🌍 **ASN provider & country** (via `ipwhois`)
* 🔓 **Shodan vulnerability data** (open ports, CVEs)
* 🔐 **TLS version, cipher, cert issuer**
* ☁️ **CDN detection**
* 🧾 **WHOIS registrar + domain age**

### ✅ 4. Behavioral 3DS Detection

* MutationObserver + Playwright-based iframe capture
* Network request tracking for CardinalCommerce, secure/auth URLs
* Detects **both redirects and injected 3DS frames**

### ✅ 5. Risk Scoring Framework

Each target is scored **0–100** based on:

* Missing 3DS evidence
* Domain age (<30 days = risky)
* Weak TLS (e.g. no TLS 1.3)
* Shodan vulnerabilities
* Known risky ASNs or missing CDN

### ✅ 6. API Integration (Bonus)

* `GET /api/risk_score?domain=…` → fetch latest score
* `POST /api/trigger_scan` → scan a new domain on demand

---

## 🧱 Project Structure

```bash
twofa_crawler/
├── flask_api.py               # Optional API server
├── scrapy.cfg                 # Scrapy config
├── requirements.txt           # Dependencies
├── README.md                  # You are here
└── twofa_crawler/
    ├── settings.py
    ├── items.py
    ├── pipelines.py
    ├── url_utils.py
    ├── shodan_enrichment.py
    ├── asn_lookup.py
    ├── tls_checker.py
    ├── whois_lookup.py
    └── spiders/
        └── checkout_spider.py
```

---

## ⚙️ Installation

```bash
git clone https://github.com/youruser/checkout-risk-intel.git
cd checkout-risk-intel

# Install Python deps
pip install -r requirements.txt

# Install browser dependencies
playwright install
```

---

## 🔐 Environment Variables

```bash
export SHODAN_API_KEY=your_shodan_key
export SECURITY_TRAILS_API_KEY=your_dns_key
export DATABASE_URL=postgresql://...
export MISP_URL=https://your.misp.instance
export MISP_API_KEY=your_misp_key
export PLAYWRIGHT_STEALTH_ENABLED=true
```

---

## 🕹️ Usage

### CLI (Scrapy)

```bash
# Scan a single URL
scrapy crawl checkout -a start_url=https://example.com

# Scan from CSV
scrapy crawl checkout -a input_file=targets.csv

# Use a mobile fingerprint
scrapy crawl checkout -a start_url=https://shop.com -a profile=us_mobile_iphone

# Output results
-o results.json
```

### API (Flask)

```bash
python flask_api.py
```

#### GET Risk Score

```
GET /api/risk_score?domain=example.com
```

#### POST New Scan

```json
POST /api/trigger_scan
{
  "url": "https://example.com",
  "profile": "default"
}
```

---

## 📊 Risk Score Example

```json
{
  "domain": "example.com",
  "risk_score": 82,
  "risk_score_details": {
    "domain_age": { "value": 12, "score": 10, "weighted_score": 10 },
    "3ds_bypass": { "value": true, "score": 10, "weighted_score": 40 },
    "tls_version": { "value": "TLSv1.2", "score": 5, "weighted_score": 4 },
    "cdn_usage": { "value": null, "score": 5, "weighted_score": 2.5 },
    "asn_reputation": { "value": "AS12345", "score": 7, "weighted_score": 8.4 }
  },
  "last_scanned": "2025-05-04T10:22:33Z"
}
```

---

## 🛠️ Limitations

* No bypass detection unless full checkout path is completed
* Behavior may vary across geographic proxies or fingerprint profiles
* Rate limits may apply (especially Shodan)
* False negatives possible on JavaScript-heavy single-page checkouts

---

## 🧠 Use Cases

* **Red teams** simulating fraud pathways
* **Payment fraud teams** at PSPs and gateways
* **Threat intelligence platforms** scanning verticals
* **Compliance/infosec** for merchant onboarding

---

## 📝 License

MIT License — use freely, modify responsibly.

---
