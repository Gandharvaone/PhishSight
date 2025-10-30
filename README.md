# PhishSight Multi-Vector Phishing Detection (Splunk)

## Overview
PhishSight is a Security Operations Center (SOC) project developed in Splunk to detect and classify phishing attacks using multiple evidence sources.  
It correlates email headers, embedded URLs, and HTML content to calculate a risk score and recommend an appropriate response action: Block, Quarantine, or Allow.  

The project simulates a real SOC workflow where phishing indicators are collected, analyzed, and visualized within Splunk for analyst decision-making.

---

## Objective

| Goal | Description |
|------|--------------|
| **Purpose** | Detect and analyze phishing attempts using multi-source data. |
| **Concept** | Combine SPF/DKIM/DMARC authentication results and HTML behavior to determine the legitimacy of emails. |
| **Outcome** | A dynamic Splunk dashboard displaying risk levels, user interactions, and analyst actions. |
| **Technology Stack** | Splunk Free (Home Instance), SPL correlation logic, CSV lookup enrichment. |

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
## Platform Setup & Lookup Configuration

**Platform:** Splunk Free Instance (Local)  
**System:** Windows 11 Home Lab  
**Dataset Sources:** Simulated phishing samples and open-source phishing datasets (SpamAssassin, PhishTank, Kaggle Email Security)

---

### Steps to Configure Lookups in Splunk

1. **Open Lookup Settings:**  
   Navigate to:  
   `Settings → Lookups → Lookup Table Files → Add New`

2. **Upload the following lookup files:**  
   - `email_events.csv`  
   - `url_signals.csv`  
   - `html_signals.csv`  
   - `honey_clicks.csv` *(optional – used for user click tracking)*  
   - *(Future enrichments)* `bad_ip_reputation.csv`, `dns_logs.csv`, `edr_logs.csv`, `login_logs.csv`  

3. **Set Permissions:**  
   After uploading each CSV, click **Permissions → Shared in App**.  
   This ensures all dashboards and correlation searches within *PhishSight* can access them.

4. **Validate the Data Load:**  
   Run the following SPL command to verify that each lookup is loaded correctly:
   ```spl
   | inputlookup email_events.csv | head 5
If the first five rows appear, your lookup is configured properly.

You can repeat for the rest

| inputlookup url_signals.csv | head 5

| inputlookup html_signals.csv | head 5 

| inputlookup honey_clicks.csv | head 5 

5. **Confirm Lookup Sharing:**
In the Lookup Definitions tab, make sure all datasets show App = search and Sharing = App.

<img width="1857" height="1220" alt="lookup_config" src="https://github.com/user-attachments/assets/36fbf943-3a20-478d-a3f3-fe6ed4573e53" />


---

## Dashboard Panels

### 1. PhishSight Risk Scoring
This panel calculates the composite risk score using email authentication and HTML behavior.

```spl
| inputlookup email_events.csv
| lookup url_signals.csv email_id 
| lookup html_signals.csv email_id 
| eval risk = 0
| eval risk = risk + if(spf_result!="pass", 20, 0)
| eval risk = risk + if(dkim_result!="pass", 10, 0)
| eval risk = risk + if(dmarc_result!="pass", 10, 0)
| eval risk_level = if(risk>50,"High",if(risk>30,"Medium","Low"))
| table email_id risk risk_level spf_result
```

**Observed Output (from report):**
- Medium-risk scores: 40 (failed SPF/DKIM)
- Low-risk scores: 0 (passed all checks)

| Email ID | Sender | Risk | Risk Level |
|-----------|---------|------|------------|
| E001 | support@amazon-secure.xyz | 40 | Medium |
| E003 | hr@corp.local | 0 | Low |
<img width="1857" height="1730" alt="risk_table_output" src="https://github.com/user-attachments/assets/2aad8087-97ce-408b-931b-39158249608a" />


---

### 2. Emails Clicked by Users
Displays phishing emails that users interacted with.

```spl
| inputlookup email_events.csv
| lookup honey_clicks.csv email_id OUTPUT click_time client_ip user_agent
| where isnotnull(click_time)
| table email_id from subject sending_domain click_time client_ip user_agent
| sort -click_time
```

**Observed Behavior:**  
Users interacted with phishing emails impersonating well-known brands such as HDFC, DHL, Apple ID, ICICI Bank, Netflix, and Flipkart.

| Email ID | Sender | Domain | IP | User Agent |
|-----------|---------|--------|--------------|
| E019 | support@hdfc-alerts.in | hdfc-alerts.in | 203.0.113.15 | Mozilla/5.0 |

<img width="1857" height="1459" alt="emails_clicked_panel" src="https://github.com/user-attachments/assets/84590300-0e82-4afa-ae47-138c8b13a2b0" />


---

### 3. Actions to be Taken (Action Center)
Translates calculated risk into a recommended SOC action.

```spl
| inputlookup email_events.csv
| lookup url_signals.csv email_id 
| lookup html_signals.csv email_id 
| eval risk = 0
| eval risk = risk + if(spf_result!="pass", 20, 0)
| eval risk = risk + if(forms_present=1, 20, 0)
| eval risk_level = if(risk > 50, "High", if(risk > 30, "Medium", "Low"))
| eval action = if(risk > 50, "Block", if(risk > 30, "Quarantine", "Allow"))
| table email_id from subject risk risk_level action
| sort - risk
```

**Output (from report):**

| Email ID | Sender | Risk | Risk Level | Action |
|-----------|---------|------|------------|---------|
| E001 | support@amazon-secure.xyz | 40 | Medium | Quarantine |
| E006 | security@googleverify-login.net | 40 | Medium | Quarantine |
| E013 | verify@aadhar-india.in | 40 | Medium | Quarantine |
| E019 | support@hdfc-alerts.in | 40 | Medium | Quarantine |
| E004 | service@paypal.com | 0 | Low | Allow |
| E015 | career@corp.local | 0 | Low | Allow |

<img width="1857" height="1760" alt="actions_panel" src="https://github.com/user-attachments/assets/600a8163-ca93-4689-941e-7abd2e2220b2" />


---

## Dashboard Summary
The PhishSight dashboard visualizes:
- Eleven medium-risk emails automatically assigned to Quarantine.
- Nine low-risk legitimate emails categorized as Allow.
- Real-time sender reputation scoring and domain authentication failures.
- Analyst guidance through Action Center.

<img width="1857" height="2423" alt="dashboard_main" src="https://github.com/user-attachments/assets/137e7bcb-9375-47fb-8ba3-816e0f973d38" />


---

## Analyst Workflow
1. Review the Risk Scoring Panel for high/medium-risk emails.  
2. Analyze Emails Clicked by Users for interaction data.  
3. Use Action Center to follow recommended responses:
   - Block for High risk
   - Quarantine for Medium risk
   - Allow for Low risk  
4. Record findings in incident management logs.

---

## Security Notes
- Only synthetic and open-source phishing datasets were used.
- No personal or production data included.
- System runs within an isolated Splunk environment.

---

## Results
Based on the simulated dataset and detection logic:

- Detection Accuracy: Successfully identified and classified all simulated phishing emails according to the defined risk criteria
- False Positives: No legitimate emails were incorrectly flagged as phishing in the test dataset
- Action Recommendations: The scoring system consistently generated appropriate actions (Quarantine/Allow) that matched expected outcomes for each test case

Note: These results demonstrate the effectiveness of the detection methodology in a controlled environment using synthetic data.

---

## Conclusion
PhishSight transforms simple lookup datasets into an operational phishing detection and response workflow within Splunk.  
It enables transparent risk scoring, actionable recommendations, and clear analyst visibility across all email telemetry layers.

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
└── splunk/
    ├── phishsight_dashboard.xml
    └── savedsearches.conf
```

**Author:** Gandharva  
**Environment:** Splunk Free Instance (Home)  
**Category:** Email Security / Phishing Detection  
**Date:** October 2025
