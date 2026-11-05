# Project 10: SIEM Detection Alert Tuning & Noise Reduction Engineering
**Category:** Detection Engineering, Security Operations (SOC), False Positive Optimization  
**Core Technologies:** Splunk Enterprise, ELK Stack, Nmap, Whitelisting Metrics, Alert Lifecycle Management

---

## 1. Project Overview
One of the most critical challenges facing modern enterprise Security Operations Centers (SOCs) is **alert fatigue**. Out-of-the-box SIEM detection rules are often too broad, causing them to flag non-malicious administrative tasks (like automated vulnerability scanners or network backups) as critical security events. When an analyst receives thousands of false-positive alerts every day, real malicious attacks can easily slip through the noise unnoticed.

This project documents a systematic **SIEM Detection Alert Tuning** exercise. By analyzing a high-volume, noisy detection rule within a staging **Splunk** environment, whitelisting thresholds and exclusion parameters were engineered to reduce alert volume by over 98%, transforming noisy data streams into high-fidelity, actionable security metrics.

---

## 2. Baseline Assessment & The Noise Profile

An automated rule named `Suspicious Inbound Network Mapping Sweep` was engineered to flag potential adversarial scanning vectors. However, the rule immediately began generating a massive footprint of false-positive data, flooding the analyst dashboard:

* **Initial Rule Metric Volume:** ~1,450 alerts per 24-hour cycle.
* **The Root Cause Analysis:** Cross-referencing the source IP addresses revealed that **99%** of the alerts were triggered by an internal vulnerability scanner appliance (`192.168.10.15`) running routine, authorized network mapping jobs.

*The Engineering Objective:* Tune the SIEM detection logic to completely suppress authorized infrastructure maintenance traffic while ensuring the rule remains 100% active to capture unauthorized rogue scanning attempts.

---

## 3. Engineering the Alert Tuning Logic (Splunk SPL)

To fix the rule logic, a multi-layered tuning strategy was implemented inside the Splunk query environment.

### The Noisy Baseline Query (Before Tuning)
```splunk
index=network_firewall action=blocked
| stats dc(dest_port) as UniquePorts by src_ip
| where UniquePorts > 20
```
*Why it failed:* It flagged *any* IP that scanned more than 20 unique ports, blindly catching the company's own security scanning tools.

### The Refined, High-Fidelity Query (After Tuning)
The query was engineered to incorporate lookups, strict network subnet constraints, and system exclusions to filter out routine traffic:

```splunk
index=network_firewall action=blocked 
    NOT (src_ip="192.168.10.15" OR src_ip="192.168.30.22") 
    NOT [| inputlookup corporate_approved_scanners.csv | fields src_ip ]
| stats dc(dest_port) as UniquePorts, values(dest_port) as TargetedPorts by src_ip, dest_ip
| where UniquePorts > 50
| sort - UniquePorts
```

### Explaining the Optimization Parameters:
1. `NOT (src_ip="192.168.10.15")`: Hard-excludes known, authorized internal system scanners from triggering the rule logic block.
2. `NOT [| inputlookup corporate_approved_scanners.csv]`: Dynamically references an asset spreadsheet lookup, automatically excluding newly onboarded administrative scanning systems without rewriting the core query.
3. `where UniquePorts > 50`: Raised the detection threshold boundary from 20 to 50 unique ports, optimizing the rule to look for aggressive, malicious scanning behavior while filtering out minor background network noise.

---

## 4. Optimization Metrics & Business ROI

Following the query tuning implementation, the rule's operational efficiency was monitored over a 7-day test window to track the reduction in noise:

| Performance Indicator | Pre-Tuning Baseline | Post-Tuning State | Net Transformation |
| :--- | :--- | :--- | :--- |
| **Daily Alert Volume** | 1,450 alerts / day | 8 alerts / day | **99.4% Noise Reduction** |
| **Analyst Triage Time** | ~4.5 Hours / day | < 10 Minutes / day | **Reclaimed Critical Focus** |
| **False Positive Rate** | 99.1% | < 2% | **High-Fidelity Optimization** |

---

## 5. Deployment Playbook
To maintain long-term alert hygiene in a standard production environment, this project enforces the following security workflows:
1. **Quarterly Lookup Auditing:** Scheduled automated reviews of `corporate_approved_scanners.csv` to ensure outdated or decommissioned servers are removed.
2. **Context Tuning Logs:** Every rule adjustment is documented in our centralized ITSM ticketing platform (**ServiceNow**) to maintain historical engineering visibility.
3. **Threshold Recalibration:** Regular automated traffic baseline scripts run to adjust port scanning triggers according to the size and scale of the infrastructure.
