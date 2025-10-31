# PhishSight Multi Vector Phishing Detection (Splunk)

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


### Components
1. Inbound Mailbox / Email Gateway – Receives legitimate and phishing emails.  
2. PhishSight Parser – Extracts SPF, DKIM, DMARC, URLs, and HTML attributes.  
3. CSV Data Exports – Structured datasets:
   - email_events.csv  
   - url_signals.csv  
   - html_signals.csv  
   - honey_clicks.csv  
4. Splunk Lookup Layer – Imports CSVs as lookup datasets.  
5. Correlation Engine (SPL) – Calculates risk and suggests remediation actions.  
6. PhishSight Dashboard – Displays live phishing analysis and decision support.

**Flow:**  
Mail → Parser → CSV Lookups → SPL Scoring → Dashboard → Analyst Response

<img width="3855" height="917" alt="Phishsight" src="https://github.com/user-attachments/assets/ffb3aca2-f94a-47b4-8f1c-38c783dfe261" />

---

## Environment Setup

**Platform:** Splunk Free Instance (Local)  
**System:** Windows 11 Home Lab  
**Dataset Sources:** Simulated phishing samples and open phishing datasets (SpamAssassin, PhishTank, Kaggle Email Security)

### Steps
1. Navigate to **Settings → Lookups → Lookup Table Files → Add New**.  
2. Upload:
   - email_events.csv  
   - url_signals.csv  
   - html_signals.csv  
   - honey_clicks.csv (optional)  
3. Set lookup permissions to “Shared in App.”  
4. Validate data:
   ```spl
   | inputlookup email_events.csv | head 5
   ```

<img width="1857" height="1220" alt="lookup_config" src="https://github.com/user-attachments/assets/754061b7-8f4b-4c72-bb0c-4cbd00293302" />


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

<img width="1857" height="1730" alt="risk_table_output" src="https://github.com/user-attachments/assets/4142ca76-e20d-42e8-80ab-c4c5794884ce" />


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

<img width="1857" height="1459" alt="emails_clicked_panel" src="https://github.com/user-attachments/assets/e9ae5a68-6f51-4ff4-851c-1513eb3d6a2e" />


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

<img width="1857" height="1760" alt="actions_panel" src="https://github.com/user-attachments/assets/9b0f43c1-3df9-409a-aa25-fd0c77542014" />


---

## Dashboard Summary
The PhishSight dashboard visualizes:
- Eleven medium-risk emails automatically assigned to Quarantine.
- Nine low-risk legitimate emails categorized as Allow.
- Real-time sender reputation scoring and domain authentication failures.
- Analyst guidance through Action Center.

<img width="1857" height="2423" alt="dashboard_main" src="https://github.com/user-attachments/assets/15a61f97-34d1-4d74-87e8-d696bcd5d8ae" />


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
