# Web Application Security Assessment
**UneeQ Interns — Cybersecurity Track**

## 1. Scope & Methodology

- **Target application:** DVWA (Damn Vulnerable Web Application), hosted on a self-managed Metasploitable2 VM
- **Environment:** VirtualBox guest, Host-only network adapter — isolated, not exposed to the internet or LAN
- **Access:** `http://192.168.56.101/dvwa/`
- **Methodology:** Manual, OWASP Top 10-style assessment covering authentication, session management, access control, input validation, and misconfiguration. Security level set to Low to evaluate baseline (unmitigated) behavior.
- **Authorization:** Self-hosted, deliberately vulnerable lab application intended for security training. No real or production systems were accessed.

## 2. Findings

### Finding 1 — Session Cookies Missing HttpOnly and Secure Flags
**Severity: Medium**

Inspection of browser storage (DevTools → Application → Cookies) shows both session cookies (`PHPSESSID`, `security`) have `HttpOnly = false` and `Secure = false`.

**Impact:** Without `HttpOnly`, client-side JavaScript (including injected XSS payloads — see Finding 5) can read the session cookie via `document.cookie`, enabling session hijacking. Without `Secure`, the cookie could be transmitted over unencrypted connections if HTTPS were later introduced without reconfiguring cookie flags.

**Recommendation:** Set the `HttpOnly` flag on all session cookies so they cannot be accessed via JavaScript, and set the `Secure` flag so cookies are only sent over HTTPS. Additionally set `SameSite=Strict` or `Lax` to reduce CSRF exposure. In PHP, this is configured via `session.cookie_httponly`, `session.cookie_secure`, and `session.cookie_samesite` in `php.ini`, or explicitly via `setcookie()` parameters.

**Evidence:** `screenshots/01-cookie-flags.png`

---

### Finding 2 — No Brute Force Protection / Rate Limiting
**Severity: High**

Multiple failed login attempts were submitted against the Brute Force module with no account lockout, CAPTCHA challenge, delay, or rate-limiting triggered at any point.

**Impact:** An attacker can attempt unlimited password guesses using automated tools (e.g. Hydra, Burp Intruder) without restriction, making credential brute-forcing practical against this login form.

**Recommendation:** Implement account lockout after a defined number of failed attempts (e.g. 5), combined with exponential backoff or a time-based delay before allowing further attempts. Add a CAPTCHA challenge after repeated failures, and log/alert on repeated failed logins from the same IP so they can be flagged for review (see Task 3/SIEM-style monitoring).

**Evidence:** `screenshots/02-bruteforce-attempt.png`

---

### Finding 3 — Credentials Transmitted via GET Request
**Severity: Medium**

The Brute Force login form submits credentials using the HTTP GET method, exposing the username and password directly in the URL:
```
http://192.168.56.101/dvwa/vulnerabilities/brute/?username=admin&password=1234568&Login=Login
```

**Impact:** Credentials submitted via GET are stored in plaintext in browser history, server access logs, and any intermediate proxy logs — increasing exposure even without an active attack in progress.

**Recommendation:** Change the login form's `method` attribute from `GET` to `POST` so credentials are sent in the request body rather than the URL. Ensure the endpoint is also served over HTTPS so the POST body itself is encrypted in transit.

**Evidence:** `screenshots/02-bruteforce-attempt.png` (URL bar)

---

### Finding 4 — Local File Inclusion (LFI)
**Severity: Critical**

The `page` parameter in the File Inclusion module does not validate or restrict the requested file path. Supplying `?page=/etc/passwd` returned the full contents of the system's `/etc/passwd` file, exposing all local user accounts, home directories, and shells.

PHP warning messages on the same page additionally disclosed the full server-side file path (`/var/www/dvwa/dvwa/includes/dvwaPage.inc.php`), aiding further attacker reconnaissance.

**Impact:** LFI of this kind can frequently be escalated to Remote Code Execution (e.g. via log poisoning or combination with an unrestricted file upload feature), making this one of the most severe findings in this assessment.

**Recommendation:** Never pass user-supplied input directly into file-inclusion functions. Use a strict allow-list of permitted page names (e.g. map `page=home` to a predefined safe path internally, rejecting anything not in the list) instead of accepting arbitrary file paths. Disable `allow_url_include` in PHP configuration, and ensure detailed error/warning messages (which leaked the server file path here) are suppressed in production via `display_errors = Off`.

**Evidence:** `screenshots/03-lfi-etc-passwd.png`

---

### Finding 5 — Stored Cross-Site Scripting (XSS)
**Severity: Critical**

The Guestbook feature (Stored XSS module) does not sanitize or encode user input before persisting and rendering it. Submitting `<script>alert('XSS')</script>` in the Name/Message fields caused the payload to execute immediately, and again automatically on every subsequent page reload — confirming the payload was stored in the backend database rather than simply reflected.

**Impact:** Unlike reflected XSS, which requires tricking a victim into clicking a malicious link, stored XSS executes for every visitor who views the affected page. Combined with Finding 1 (missing HttpOnly), this could be used to silently steal session cookies from any user, including administrators.

**Recommendation:** Encode all user-supplied data on output using context-aware escaping — in PHP, `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')` before rendering any user input into HTML. Additionally apply input validation/sanitization on write (e.g. strip or reject `<script>` tags), and deploy a Content-Security-Policy (CSP) header to restrict inline script execution as a defense-in-depth measure.

**Evidence:** `screenshots/04-stored-xss-alert.png`

---

### Finding 6 — OS Command Injection
**Severity: Critical**

The Command Execution module (a "ping" utility) passes user-supplied input directly to a shell command without sanitization. Submitting `127.0.0.1 && whoami` appended the output `www-data` after the ping results, confirming arbitrary command execution under the web server's process identity. A follow-up payload, `127.0.0.1 && cat /etc/passwd`, successfully dumped the full system user list, confirming full shell-level command injection.

**Impact:** Command injection of this kind typically leads to full server compromise — an attacker could read sensitive files, write backdoors, create new user accounts, or pivot to other systems on the network.

**Recommendation:** Avoid shelling out to OS commands from application code wherever possible — use native language functions instead (e.g. PHP's built-in socket/network functions rather than invoking the system `ping` binary). Where shell execution is unavoidable, use parameterized/escaped calls (e.g. `escapeshellarg()`) and strictly validate input against an expected format (e.g. a regex confirming the input is a valid IPv4 address) before passing it anywhere near a shell command.

**Evidence:** `screenshots/05-command-injection-whoami.png`, `screenshots/06-command-injection-passwd.png`

---

## 3. Risk Matrix

| # | Finding | Severity | Primary Impact |
|---|---|---|---|
| 1 | Missing HttpOnly/Secure cookie flags | Medium | Session hijacking via XSS |
| 2 | No brute force protection | High | Credential compromise via automated guessing |
| 3 | Credentials sent via GET | Medium | Credential exposure in logs/history |
| 4 | Local File Inclusion | Critical | Sensitive file disclosure, path to RCE |
| 5 | Stored XSS | Critical | Session hijacking, affects all visitors |
| 6 | OS Command Injection | Critical | Full server compromise |

## 4. Remediation Priority Checklist

A consolidated checklist for tracking fixes (full detail is under each finding above):

- [ ] Finding 1 — Add `HttpOnly`/`Secure`/`SameSite` flags to session cookies
- [ ] Finding 2 — Add login rate limiting / account lockout
- [ ] Finding 3 — Switch login form from GET to POST
- [ ] Finding 4 — Replace free-form file path input with an allow-list
- [ ] Finding 5 — Escape all user-supplied output (`htmlspecialchars`) + add CSP header
- [ ] Finding 6 — Remove shell command usage or strictly validate/escape input before use
- [ ] General — Disable `phpinfo()` and verbose error/warning output in any non-development environment

## 5. Summary

This assessment identified 6 distinct vulnerabilities across authentication, session management, and input validation categories, including three **Critical**-severity issues (LFI, Stored XSS, and OS Command Injection) that could individually lead to full compromise of the application or underlying server. The presence of multiple critical, independently exploitable vulnerabilities indicates the application was configured at a low security baseline with minimal input validation across nearly all tested attack surfaces. All findings were reproduced in an isolated, authorized lab environment for training purposes only.
