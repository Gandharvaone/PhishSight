# PhishSight — Multi-Vector Phishing Detection (Splunk)

**Status:** Email‑focused build (current).  
**Scope clarity:** This project *only* uses email telemetry CSVs. Banking/SOC datasets you mentioned (bank_txn, dns_logs, edr_logs, login_logs, etc.) are **not** used in the **current** SPL and dashboards. They can be added later as optional enrichments (see "Future Extensions").

---

## Objective

| Goal | Description |
|------|-------------|
| **Purpose** | Detect and analyze phishing attempts using multi-source **email** data. |
| **Concept** | Combine SPF/DKIM/DMARC, URL intelligence, and HTML behaviors to score risk. |
| **Outcome** | A Splunk dashboard showing risk, user clicks, and recommended actions. |
| **Stack** | Splunk Free (local), SPL correlation logic, CSV lookup enrichment. |

---

## Architecture Overview

**Diagram:** `diagrams/phishsight_architecture.png`

**Components**
1) **Inbound Mailbox / Email Gateway** → sample emails  
2) **PhishSight Parser** → extracts headers, URLs, HTML indicators  
3) **CSV Data Exports (USED):**  
   - `email_events.csv` (one row per email; spf_result, dkim_result, dmarc_result, from, subject, sending_domain, etc.)  
   - `url_signals.csv` (per email_id; url, url_suspect, domain_age_days, brand_impersonation, etc.)  
   - `html_signals.csv` (per email_id; forms_present, obfuscation, external_js, data_uri, etc.)  
   - `honey_clicks.csv` (per email_id; click_time, client_ip, user_agent)  
4) **Splunk Lookup Layer** → import CSVs as lookups  
5) **Correlation Engine (SPL)** → computes `risk` & `risk_level`  
6) **PhishSight Dashboard** → Risk Scoring, Emails Clicked, Action Center

Mail → Parser → CSV Lookups → **SPL Scoring** → Dashboard → Analyst Response

---

## Data Inventory (Used vs Not Used)

A single truth table so reviewers know exactly what powers this build:

- **USED now:** `email_events.csv`, `url_signals.csv`, `html_signals.csv`, `honey_clicks.csv`  
- **NOT used now (banking/SOC datasets):** `bank_txn.csv`, `dns_logs.csv`, `edr_logs.csv`, `login_logs.csv`, `bad_ip_reputation.csv`, `first_payments.csv`, `known_customers.csv`, `merchant_list.csv`, `mule_accounts.csv`, `new_devices.csv`, `risky_merchants.csv`, `trusted_devices.csv`

Source file: `data_inventory.csv`

---

## Dashboard Panels (SPL)

### 1) PhishSight Risk Scoring (more natural distribution)
```spl
| inputlookup email_events.csv
| lookup url_signals.csv email_id
| lookup html_signals.csv email_id
| eval risk = 0
| eval risk = risk 
    + if(spf_result!="pass", 20, 0)
    + if(dkim_result!="pass", 10, 0)
    + if(dmarc_result!="pass", 10, 0)
    + if(coalesce(url_suspect,0)=1, 15, 0)
    + if(coalesce(forms_present,0)=1, 15, 0)
    + if(coalesce(brand_impersonation,0)=1, 10, 0)
    + if(coalesce(domain_age_days,9999)<14, 5, 0)
    + if(coalesce(html_obfuscation,0)=1, 10, 0)
| eval risk_level = case(
    risk>=60,"High",
    risk>=30,"Medium",
    true(),"Low"
)
| table email_id from subject sending_domain risk risk_level spf_result dkim_result dmarc_result url_suspect forms_present
| sort - risk
```

### 2) Emails Clicked by Users
```spl
| inputlookup email_events.csv
| lookup honey_clicks.csv email_id OUTPUT click_time client_ip user_agent
| where isnotnull(click_time)
| table email_id from subject sending_domain click_time client_ip user_agent
| sort - click_time
```

### 3) Action Center (recommendations)
```spl
| inputlookup email_events.csv
| lookup url_signals.csv email_id
| lookup html_signals.csv email_id
| eval risk=0
| eval risk=risk
    + if(spf_result!="pass",20,0)
    + if(coalesce(forms_present,0)=1,20,0)
    + if(coalesce(url_suspect,0)=1,15,0)
| eval risk_level = case(risk>=60,"High", risk>=30,"Medium", true(),"Low")
| eval action = case(risk_level="High","Block", risk_level="Medium","Quarantine", true(),"Allow")
| table email_id from subject risk risk_level action
| sort - risk
```

> These tweaks ensure scores aren’t all **40**; they vary naturally with more signals.

---

## Results Snapshot (example)
- High/Medium/Low buckets reflect authentication, URL, and HTML signals.  
- Action Center suggests **Block/Quarantine/Allow** accordingly.

---

## Future Extensions (optional)
If you *want* to blend general SOC datasets later, here’s how they would fit **without** changing today’s build:
- **DNS enrichment:** join `dns_logs.csv` by `client_ip` after a click → add +5 risk if domain newly seen.  
- **EDR correlation:** join `edr_logs.csv` by `endpoint_id` → add +10 risk if malware/IOC on the same host.  
- **Auth context:** join `login_logs.csv` by `user/email` → add +5 risk for anomalous sign-in near click time.  
- **Banking telemetry** (separate fraud project) should live in a **different repo** to avoid scope confusion.

---

## Repository Structure
```
PhishSight/
├── README.md
├── diagrams/
│   └── phishsight_architecture.png
├── screenshots/
│   ├── dashboard_main.png
│   ├── actions_panel.png
│   ├── emails_clicked_panel.png
│   ├── lookup_config.png
│   └── csv_preview.png
├── data/
│   ├── email_events.csv
│   ├── url_signals.csv
│   ├── html_signals.csv
│   └── honey_clicks.csv
├── data_inventory.csv
└── splunk/
    ├── phishsight_dashboard.xml
    └── savedsearches.conf
```

**Author:** Gandharva • **Category:** Email Security / Phishing Detection • **Date:** October 2025

---

## Data Inventory (Auto‑generated)

See: `data_inventory.csv` and `data_dictionary.csv` for full details (rows, columns, readability).  
Newly uploaded datasets are listed and currently marked **NOT used** unless part of the 4 core email CSVs.

**Files discovered under /mnt/data:**  
bad_ip_reputation.csv, bank_txn.csv, dns_logs.csv, edr_logs.csv, first_payments.csv, known_customers.csv, login_logs.csv, merchant_list.csv, mule_accounts.csv, new_devices.csv, risky_merchants.csv, trusted_devices.csv

---

## Enrichment Ideas (Next Iteration)

See: `enrichment_ideas.csv` for a per‑file suggestion on how to plug into PhishSight scoring.  
These are optional and won’t break the current dashboard. Implement one by one.

### Example SPL snippet to add IP reputation enrichment (if fields exist)
```spl
| inputlookup email_events.csv
| lookup url_signals.csv email_id
| lookup html_signals.csv email_id
| lookup honey_clicks.csv email_id OUTPUTNEW click_time client_ip
| lookup bad_ip_reputation.csv client_ip OUTPUTNEW reputation
| eval risk = 0
| eval risk = risk
    + if(spf_result!="pass",20,0)
    + if(coalesce(forms_present,0)=1,20,0)
    + if(coalesce(url_suspect,0)=1,15,0)
    + if(reputation="malicious",10,0)
| eval risk_level = case(risk>=60,"High", risk>=30,"Medium", true(),"Low")
| eval action = case(risk_level="High","Block", risk_level="Medium","Quarantine", true(),"Allow")
| table email_id from subject client_ip reputation risk risk_level action
| sort - risk
```

> Note: We use `OUTPUTNEW` + `coalesce()` so missing columns won’t error; they just won’t add risk.