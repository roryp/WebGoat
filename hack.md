
## 0) Check your endpoints (Docker defaults)

* **WebGoat UI:** `http://127.0.0.1:8080/WebGoat`
  (If you haven’t yet, click **Register** to create a user, then sign in.) ([Docker Hub][1], [ACTE Technologies][2])
* **WebWolf (for hosting CSRF/phish pages):** `http://127.0.0.1:9090/WebWolf` (log in with the same account). ([Docker Hub][1], [Medium][3])

**Tip:** In VS Code, paste each line below as a comment (or plain text) to get Copilot’s suggestion, **copy the suggested payload**, and paste it into the WebGoat lesson’s input.

---

## Run guide (one per category)

### 1) SQL Injection → *Injection Flaws → SQL Injection*

**Prompt in VS Code:**
`// In WebGoat v8, suggest a single-string SQL injection to bypass login`
**Run:** Open the **SQL Injection** lesson. Paste Copilot’s string into the vulnerable **username / id** field, put anything in the other field, **Submit**. (You should see unauthorized data/bypass if the input is right.)

### 2) Reflected XSS → *XSS → Reflected XSS*

**Prompt:**
`<!-- In WebGoat, propose a minimal reflected XSS input that pops an alert -->`
**Run:** Open **Reflected XSS**. Paste Copilot’s snippet into the **search/message** field, **Submit** → browser alert should fire.

### 3) CSRF (auto-POST) → *Cross-Site Request Forgery (basic/advanced)*

**Prompt:**
`<!-- In WebGoat, generate a minimal auto-submitting CSRF POST form with placeholder fields -->`
**Run (two easy ways):**

* **With WebWolf:** In **WebWolf** create `attack.html`, paste Copilot’s form, save, open it in WebWolf → it auto-submits to WebGoat and completes the step. ([Medium][3])
* **Local file:** Save `attack.html` on your machine and open it in a browser (works for many labs).
  *(Fill action/field names to match the lesson page.)*

### 4) Broken Access Control / IDOR → *Access Control → Insecure Direct Object Reference*

**Prompt:**
`// In WebGoat, suggest a simple URL/query parameter tamper (employee_id) to view another user`
**Run:** In the IDOR lesson, perform the action once, open **DevTools → Network → Right-click → Edit and Resend** (or copy as cURL), change the `employee_id` (or similar) to a different value, **Resend**. You should see another user’s data.

### 5) Session Management (predictable IDs) → *Session Management → Hijacking/Predictable*

**Prompt:**
`// In WebGoat, outline a quick script to guess sequential session IDs`
**Run:** Follow the lesson to gather a few issued IDs, then use Copilot’s tiny script idea (or just try adjacent values in the lab’s input) to submit **nearby IDs** until the lesson confirms a match.

### 6) Parameter Tampering → *Client-Side Validation / Hidden Fields*

**Prompt:**
`// In WebGoat, example of changing a hidden 'price' field before submit`
**Run:** In the **shopping/hidden field** lesson, start checkout, intercept the request (DevTools or proxy), **edit the hidden `price`** to a tiny value, **Resend** → lesson should validate the tamper was accepted.

### 7) Path Traversal → *Access Control → Path-based / Directory Traversal*

**Prompt:**
`// In WebGoat, propose a filename/path traversal string to escape a folder and read a config file`
**Run:** In the traversal lesson’s **file path** box, paste Copilot’s `../` pattern, **View/Submit** to fetch a restricted file (the lab will confirm). ([Medium][4])

### 8) Log Injection → *General → Log Spoofing*

**Prompt:**
`// In WebGoat, suggest a username value that injects a newline to forge an extra log entry`
**Run:** In the **Log Spoofing** lesson, paste Copilot’s input in the **username** field, **Submit** → click the lesson’s **Show logs** to see the forged line.

### 9) XXE → *Injection Flaws → XML External Entity*

**Prompt:**
`<!-- For WebGoat lab, craft a test XML with a harmless external entity to fetch /etc/passwd -->`
**Run:** In the XXE lesson’s **XML textarea**, paste Copilot’s XML, **Submit** → the response should include the entity expansion (the lab detects success).

### 10) DOM XSS → *XSS → DOM-based*

**Prompt:**
`// In WebGoat, propose a URL hash/fragment payload that triggers DOM-based alert without server changes`
**Run:** Open the **DOM XSS** page, append Copilot’s fragment to the page URL (after `#`), **Enter** → alert fires if the page sinks the fragment unsafely.

---

### Optional tooling tips

* **Burp/ZAP** make “Edit and resend” and CSRF testing faster (not required but handy). The official Docker run maps both ports for **WebGoat (8080)** and **WebWolf (9090)** out of the box. ([Docker Hub][1])

> All of this stays inside your lab; do **not** aim these at real sites. WebGoat exists precisely for this purpose. ([OWASP Foundation][5])

If you want, I can turn this into a **one-page run sheet** (printable) with checkboxes for your live demo.

[1]: https://hub.docker.com/r/webgoat/webgoat?utm_source=chatgpt.com "Docker Image - webgoat"
[2]: https://www.acte.in/webgoat-tutorial?utm_source=chatgpt.com "WebGoat: A Complete Guide Tutorial | CHECK-OUT"
[3]: https://medium.com/%40develouise/getting-started-with-webgoat-and-webwolf-using-jar-d06431883cc2?utm_source=chatgpt.com "Getting Started with WebGoat and WebWolf using JAR."
[4]: https://pvxs.medium.com/webgoat-path-traversal-2-3-4-561ba00b020e?utm_source=chatgpt.com "WebGoat Path Traversal 2 3 4 - PVXs - Medium"
[5]: https://owasp.org/www-project-webgoat/?utm_source=chatgpt.com "OWASP WebGoat"
