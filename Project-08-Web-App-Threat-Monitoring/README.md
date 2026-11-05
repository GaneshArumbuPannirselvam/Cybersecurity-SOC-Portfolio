# Project 8: Web Application Threat Monitoring & Web Log Vulnerability Analysis
**Category:** Security Operations, Web Application Security, Threat Hunting  
**Core Technologies:** Splunk Enterprise, Apache HTTP Server, Kali Linux, Linux Command Line (Grep/Regex), Web Application Firewalls (WAF)

---

## 1. Project Overview
Web applications are highly targeted external boundaries for enterprise networks. Attackers constantly scan public-facing ports, attempting to find database flaws via **SQL Injection (SQLi)** or execute malicious scripts through **Cross-Site Scripting (XSS)** vulnerabilities. If these applications lack specialized protection, your web server access logs serve as the primary source of truth to discover if an application has been compromised.

This project outlines an active web threat-monitoring framework. It analyzes raw, unformatted **Apache server access logs** to identify real-world malicious payload syntax launched from an adversarial system node. It demonstrates how to parse these signatures using both basic command-line regex parameters and automated **Splunk SPL queries** to isolate web application threat actors instantly.

---

## 2. Analyzing Vulnerability Footprints in Web Server Logs

When automated vulnerability scanners or human threat actors attack a web form, the characters they type are permanently recorded in the web server's access log file. Standard human traffic accesses basic paths (e.g., `/index.html`), whereas attackers inject database syntax or script tags.

### Case Study 2.1: Isolating a SQL Injection (SQLi) Payload
Below is a raw log string extracted from our staging server access log (`access.log`), documenting a malicious database manipulation attempt:
```text
192.168.1.84 - - [24/Oct/2026:15:32:10 -0400] "GET /product.php?id=1%20UNION%20SELECT%20NULL,username,password%20FROM%20users HTTP/1.1" 200 4522 "-" "Mozilla/5.0 (Kali Linux)"
```
* **Analysis Finding:** The presence of `%20UNION%20SELECT%20` (URL-encoded space + SQL keywords) proves the client is actively attempting to bypass the web front-end logic and extract the raw contents of the backend database table `users`.

### Case Study 2.2: Isolating a Cross-Site Scripting (XSS) Payload
Below is a second access log sample documenting an injection attempt designed to hijack other users' session cookies:
```text
192.168.1.84 - - [24/Oct/2026:15:35:45 -0400] "GET /search.php?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1" 200 1204 "-" "Mozilla/5.0 (Kali Linux)"
```
* **Analysis Finding:** The string reveals URL-encoded script brackets (`%3Cscript%3E` converts to `<script>`). The attacker is attempting to store or reflect an executive script payload within the web query context.

---

## 3. Threat Hunting Implementation (Linux CLI vs. Splunk)

To pull these high-fidelity alerts out of a high-volume production environment generating millions of routine log lines, specific text filtration filters must be enforced.

### Method 3.1: Command Line Regex Triage (The "Hot Fix" Method)
If an analyst needs to parse raw logs on a standalone server during an ongoing incident investigation, these optimized `grep` expressions isolate web vectors immediately:
```bash
# Search for SQL Union or Select manipulation signatures inside web logs
grep -iE "UNION|SELECT|OR 1=1" /var/log/apache2/access.log

# Search for Script tags or iframe injection indicators
grep -iE "(<|%3C)script(|%3E|>)" /var/log/apache2/access.log
```

### Method 3.2: Scale Automation with SIEM Engineering (Splunk SPL)
To continually monitor and create active automated alert playbooks for corporate applications, a custom **Splunk query** was engineered to track down and chart web attacks:

```splunk
index=web_server_logs (method=GET OR method=POST)
| eval payload = lower(uri)

| regex payload="(union\s+select|select\s+.*\s+from|or\s+1\s*=\s*1|<script>|%3cscript%3e)"
| stats count, values(user_agent) as Scanner_Type by src_ip, uri, status
| sort - count
```
* **Logic Explanation:** The query normalizes the uniform resource identifier (`uri`) strings to lowercase, passes them through a strict regular expression filter to intercept SQL and XSS strings, groups the attacks by the source IP, and lists what browser or tool the attacker used.

---

## 4. Remediation & Defensive Defenses Playbook

Upon detecting continuous web application payload alerts tracking back to a source IP, the following incident playbooks are prioritized:
1. **Network Layer Drop:** Add an immediate IP drop rule into our perimeter **pfSense Virtual Firewall** or Edge Router ACL to stop the attacker's traffic at the network boundary.
2. **WAF Deployment:** Implement an inline Web Application Firewall (WAF) such as **ModSecurity** with core rule sets configured to instantly intercept and block SQLi/XSS parameters before they reach the web application daemon layer.
3. **Source Code Patching:** Hand off the logs to the software engineering team to implement strictly enforced **Parameterized Queries / Prepared Statements** and input sanitization to eliminate the code vulnerability completely.
