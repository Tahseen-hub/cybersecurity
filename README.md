# UneeQ Interns — Cybersecurity Track Internship Projects

This repository contains all completed tasks for the Cybersecurity track of the UneeQ Interns internship program. All testing was performed in an isolated, self-hosted lab environment (DVWA and Metasploitable2 running on a Host-only VirtualBox network) for training purposes only.

## Tasks

### [Task 1 — SQL Injection Lab (Detect, Exploit, Fix)](./task-1-sql-injection-lab/)
Detected, exploited, and remediated a SQL Injection vulnerability in DVWA across its Low, Medium, and High security levels. Identified that the Medium-level mitigation could still be bypassed using a quote-less UNION payload, and implemented a parameterized query fix that closes the vulnerability entirely.

**Deliverables:** Full lab report, evidence screenshots, fixed code (`fix/fixed_query.php`)

---

### [Task 2 — Web Application Security Assessment](./task-2-web-app-security-assessment/)
Conducted an OWASP Top 10-style security assessment of DVWA, covering authentication, session management, access control, and input validation. Identified 6 vulnerabilities, including Local File Inclusion, Stored XSS, and OS Command Injection, each documented with severity ratings, impact, and remediation steps.

**Deliverables:** Full assessment report, evidence screenshots, risk matrix, remediation checklist

---

### [Task 3 — Vulnerability Assessment Report](./task-3-vulnerability-assessment/)
Performed a vulnerability assessment of a Metasploitable2 target using Nmap, including a full port/service scan and a targeted vulnerability script scan. Identified multiple critical findings, including a backdoored FTP service (CVE-2011-2523) that was actively exploited by the scan itself, confirming unauthenticated root access.

**Deliverables:** Full assessment report, risk matrix, raw Nmap scan output (`nmap_full_scan.txt`, `nmap_vuln_scan.txt`)

---

## Environment

- **Target applications:** DVWA (Damn Vulnerable Web Application), Metasploitable2
- **Virtualization:** Oracle VirtualBox, Host-only network adapter (isolated from internet/LAN)
- **Tools used:** Nmap, DVWA built-in modules, MySQLi (prepared statements)

## Note

All vulnerabilities documented here were found and tested exclusively within this authorized, self-hosted lab environment. No real or production systems were accessed or tested at any point.
