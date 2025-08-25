Got it — here are your **Copilot prompts mapped to the relevant WebGoat lessons** (Docker run; no code changes, just payloads/inputs):

* **SQL Injection** → *SQL Injection*
  `// In WebGoat v8, suggest a single-string SQL injection to bypass login`  ([GitHub][1])

* **Reflected XSS** → *Reflected XSS*
  `<!-- In WebGoat, propose a minimal reflected XSS input that pops an alert -->`  ([GitHub][1])

* **Stored XSS** → *Stored XSS*
  `<!-- In WebGoat, suggest a stored XSS comment that will execute for an admin viewer -->`  ([GitHub][1])

* **CSRF** → *Cross-Site Request Forgery (CSRF)* (incl. *CSRF token bypass* / *prompt bypass*)
  `<!-- In WebGoat, generate a minimal auto-submitting CSRF POST form with placeholder fields -->`  ([GitHub][1])

* **Broken Access Control / IDOR** → *IDOR (A01: Broken Access Control)*
  `// In WebGoat, suggest a simple URL/query parameter tamper (employee_id) to view another user`  ([Medium][2], [Medium][3])

* **Path Traversal-style bypass** → *Path-Based Access Control*
  `// In WebGoat, propose a filename/path traversal string to escape a folder and read a config file`  ([GitHub][1])

* **Log Injection** → *Log Spoofing*
  `// In WebGoat, suggest a username value that injects a newline to forge an extra log entry`  ([GitHub][1])

* **XXE** → *XML External Entity (XXE)*
  `<!-- For WebGoat lab, craft a test XML with a harmless external entity to fetch /etc/passwd -->`  ([GitHub][1])

* **DOM XSS** → *DOM XSS* (also *DOM Injection*)
  `// In WebGoat, propose a URL hash/fragment payload that triggers DOM-based alert without server changes`  ([GitHub][1])

* **Session Fixation** → *Session Fixation*
  `// In WebGoat, construct a phishing-style URL that pins a known SID (e.g., SID=12345)`  ([GitHub][1])

*(Use strictly inside your WebGoat lab.)*

[1]: https://github.com/WebGoat/WebGoat-Lessons "GitHub - WebGoat/WebGoat-Lessons: 7.x - The WebGoat STABLE lessons supplied by the WebGoat team."
[2]: https://callgh0st.medium.com/webgoat-solution-guessing-and-predicting-patterns-insecure-direct-object-references-bde27b9c12ea?utm_source=chatgpt.com "Webgoat Solution: Guessing and Predicting Patterns ..."
[3]: https://pvxs.medium.com/webgoat-idor-5-f3b0beba931?utm_source=chatgpt.com "WebGoat IDOR 5 - PVXs - Medium"
