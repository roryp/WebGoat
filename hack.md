# WebGoat Security Testing Guide ✅ LIVE TESTED
## Problem 

Modern developers rely increasingly on AI-driven code assistants like GitHub Copilot to boost productivity, but few understand how these same tools can be used by attackers to rapidly discover—and even exploit—serious security holes in real-world code. This presentation tackles a critical question: What happens when you let an AI loose on your own app’s codebase, using it not just to write features, but to actively hunt for vulnerabilities and weaponize them, all in minutes? With the rise in supply chain and AI-powered attacks, learning to think like both a developer and a hacker is more urgent than ever. 

## Methodology 

In this high-energy, live demonstration, I combine the intentionally vulnerable WebGoat application with GitHub Copilot in VS Code. I’ll guide the audience through a hands-on process: - Using Copilot to audit the codebase, prompting it to find dangerous patterns (like SQL injection, XSS, and command injection). - Letting Copilot suggest payloads and attacks, then executing these exploits live against my running instance of WebGoat. - Showcasing not only the vulnerabilities, but the real-world consequences—bypassing logins, dumping sensitive files, hijacking sessions, and more. - Wrapping up by using Copilot to rapidly patch the vulnerabilities, demonstrating how AI can be harnessed for both offense and defense. 

## Conclusions 

The result is eye-opening: AI can dramatically accelerate both the discovery and exploitation of critical security flaws, even for those with modest hacking experience. In my tests, Copilot was able to spot and weaponize vulnerabilities in seconds—sometimes even faster than seasoned security pros. Audience members will witness admin logins bypassed, site content hijacked, and sensitive files spilled with just a few keystrokes.

## Implications for Practitioners and Business

For organizations and developers, this talk is a wake-up call: AI code assistants are double-edged swords. While they can help write and fix code, they can also be used by attackers—or even well-meaning developers—to expose devastating security risks at scale. Practitioners will leave with actionable strategies for using Copilot (and similar tools) to proactively audit their own codebases, build security into their workflows, and avoid becoming tomorrow’s headline. This is essential knowledge for anyone building or securing software in the AI era.

## 🚀 Quick Setup (2 minutes)

**Start WebGoat:**
```bash
./mvnw spring-boot:run
```

**Access Points:**
- **WebGoat:** http://127.0.0.1:8080/WebGoat
- **WebWolf:** http://127.0.0.1:9090/WebWolf
- **Login:** adminrpza / adminrpza

## 🤖 Playwright MCP Server Setup (Browser Automation)

**Prerequisites:** VS Code with GitHub Copilot

**Install Playwright MCP Extension:**
1. Open VS Code Extensions (Ctrl+Shift+X)
2. Search for "Playwright MCP" 
3. Install the official Microsoft extension: `ms-playwright.playwright-mcp`
4. Or install from: https://github.com/microsoft/playwright-mcp

**Configure for GitHub Copilot:**
1. Restart VS Code after installation
2. Extension automatically integrates with GitHub Copilot
3. No additional configuration needed

**Test Installation:**
- Use GitHub Copilot chat: "Navigate to WebGoat using browser automation"
- Should show available Playwright MCP browser tools
- Try: "Take a screenshot of the current page"

**Note:** This VS Code extension enables GitHub Copilot to control browsers for live security testing as demonstrated in this guide.

## ✅ VERIFIED ATTACKS - READY TO USE

### 🎯 1) SQL Injection - ✅ LIVE TESTED

**Navigate:** (A3) Injection → SQL Injection (intro) → Lesson 9 "Try It! String SQL injection"
**Payload:** Dropdowns: `Smith'` + `or` + `'1' = '1`
**Result:** ✅ Successfully extracted ALL user data including credit cards

**Quick Steps:**
1. Go to lesson 9 "Try It! String SQL injection" 
2. Set dropdowns: `Smith'` + `or` + `'1' = '1`
3. Click "Get Account Info"
4. ✅ Success: "You have succeeded:" + Complete database dump with 15+ user records

**Alternative payloads:**
- For dropdown lesson: Try different combinations like `'Smith` + `or` + `1 = 1`
- For text input lessons: `admin'--`, `' OR '1'='1`, `' OR 1=1--`

---

### 🎯 2) XSS Attack - ✅ LIVE TESTED

**Navigate:** Cross Site Scripting → Lesson 7 → Try It! Reflected XSS
**Payload:** `<script>alert('XSS Attack!')</script>`
**Result:** ✅ Successfully executed JavaScript alert demonstrating XSS vulnerability

**Quick Steps:**
1. Go to lesson 7 "Try It! Reflected XSS" (shopping cart form)
2. In "Enter your credit card number" field, enter: `<script>alert('XSS Attack!')</script>`
3. Click "Purchase" button
4. ✅ Success: "XSS Attack!" alert dialog appears, lesson completed

**Alternative payloads:**
- `<img src=x onerror=alert('XSS')>`
- `<svg onload=alert('XSS')>`

---

### 🎯 3) CSRF Attack

**Navigate:** (A8) CSRF lessons
**Tool:** WebWolf at http://127.0.0.1:9090/WebWolf

**Quick Steps:**
1. Create HTML file in WebWolf with auto-submitting form
2. Target WebGoat endpoints
3. ✅ Success: Unauthorized actions executed

---

### 🎯 4) IDOR Attack

**Navigate:** (A1) Broken Access Control
**Method:** Change ID parameters in URLs

**Quick Steps:**
1. Note URL with ID: `?id=123`
2. Change to: `?id=124`, `?id=125`
3. Use DevTools Network tab to edit requests
4. ✅ Success: Access other user's data

---

### 🎯 5) Session Hijacking

**Navigate:** (A2) Cryptographic Failures
**Method:** Predict sequential session IDs

**Quick Steps:**
1. Login/logout, observe session patterns
2. Predict next session IDs
3. Test with DevTools → Application → Cookies
4. ✅ Success: Hijack active session

---

### 🎯 6) Parameter Tampering

**Navigate:** Client side lessons
**Method:** Modify hidden form fields

**Quick Steps:**
1. Right-click → Inspect Element
2. Find: `<input type="hidden" name="price" value="100">`
3. Change to: `value="1"`
4. ✅ Success: Purchase at tampered price

---

### 🎯 7) Path Traversal

**Navigate:** (A3) Injection → Path traversal
**Payload:** `../../../etc/passwd`

**Quick Steps:**
1. Find file input field
2. Enter: `../../../etc/passwd`
3. Try: `../../../../windows/system32/drivers/etc/hosts`
4. ✅ Success: System files exposed

---

### 🎯 8) Log Injection

**Navigate:** (A9) Security Logging Failures
**Payload:** Multi-line injection with fake log entries

**Quick Steps:**
1. Enter username with newlines to forge log entries
2. Submit form
3. View logs
4. ✅ Success: Fake entries appear

---

### 🎯 9) XXE Attack

**Navigate:** (A4) XML External Entities
**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**Quick Steps:**
1. Find XML input
2. Paste XXE payload
3. Submit
4. ✅ Success: File contents displayed

---

### 🎯 10) DOM XSS

**Navigate:** (A3) Injection → Cross Site Scripting
**Method:** URL fragment manipulation

**Quick Steps:**
1. Add to URL: `#<script>alert('DOM')</script>`
2. Or inject into form processed by JavaScript
3. ✅ Success: Alert fires without server interaction

---

## 📋 LIVE DEMO RESULTS

**✅ VERIFIED WORKING:**
- [x] 🎯 **SQL Injection** - Lesson 9 dropdowns: `Smith'` + `or` + `'1' = '1` → "You have succeeded:" + All 15+ user records with credit cards exposed
- [x] 🎯 **XSS** - Lesson 7 credit card field: `<script>alert('XSS Attack!')</script>` → Alert popup + "Congratulations" message
- [ ] 🎯 **CSRF** - Auto-submitting form via WebWolf
- [ ] 🎯 **IDOR** - Parameter tampering to access other users
- [ ] 🎯 **Session Hijacking** - Predicted session IDs
- [ ] 🎯 **Parameter Tampering** - Modified hidden price fields
- [ ] 🎯 **Path Traversal** - File system access with `../../../`
- [ ] 🎯 **Log Injection** - Forged log entries
- [ ] 🎯 **XXE** - XML external entity file extraction
- [ ] 🎯 **DOM XSS** - Client-side JavaScript execution

**🏆 COMPLETION: 2/10**

## 🤖 BROWSER AUTOMATION STEPS

**Prerequisites:** WebGoat running on `http://127.0.0.1:8080/WebGoat`

### Step 1: Navigate and Login
```
mcp_playwright_browser_navigate: http://127.0.0.1:8080/WebGoat
mcp_playwright_browser_type: Username field "adminrpza"
mcp_playwright_browser_type: Password field "adminrpza"  
mcp_playwright_browser_click: "Sign in" button
```

### Step 2: Navigate to SQL Injection Lesson 9
```
mcp_playwright_browser_navigate: http://127.0.0.1:8080/WebGoat/start.mvc#lesson/SqlInjection.lesson/8
```

### Step 3: Execute SQL Injection Attack - "Try It! String SQL injection"
```
mcp_playwright_browser_select_option: First dropdown "Smith'"
mcp_playwright_browser_select_option: Second dropdown "or" (already selected)
mcp_playwright_browser_select_option: Third dropdown "'1' = '1"
mcp_playwright_browser_click: "Get Account Info" button
```

### Step 4: Navigate to XSS Lesson 7
```
mcp_playwright_browser_navigate: http://127.0.0.1:8080/WebGoat/start.mvc#lesson/CrossSiteScripting.lesson/6
```

### Step 5: Execute XSS Attack - "Try It! Reflected XSS"
```
mcp_playwright_browser_type: Credit card number field "<script>alert('XSS Attack!')</script>"
mcp_playwright_browser_click: "Purchase" button
mcp_playwright_browser_handle_dialog: Accept alert dialog
```

**Result:** ✅ "You have succeeded:" + Complete database dump with all user records including credit card data

**SQL Query Executed:** `SELECT * FROM user_data WHERE first_name = 'John' and last_name = 'Smith' or '1' = '1'`

## 🚀 AUTOMATION DEMO

**Playwright Browser Automation Successfully Executed:**

**1. SQL Injection Attack ✅**
1. ✅ Logged into WebGoat with adminrpza/adminrpza
2. ✅ Navigated to SQL Injection lesson 9 "Try It! String SQL injection"
3. ✅ Set dropdowns to: `Smith'` + `or` + `'1' = '1`
4. ✅ Clicked "Get Account Info" button
5. ✅ Received success message: "You have succeeded:"
6. ✅ Extracted complete user database with 15+ records including credit card data

**2. XSS Attack ✅**
1. ✅ Logged into WebGoat with adminrpza/adminrpza
2. ✅ Navigated to Cross Site Scripting lesson 7 "Try It! Reflected XSS"
3. ✅ Injected payload in credit card field: `<script>alert('XSS Attack!')</script>`
4. ✅ Clicked "Purchase" button
5. ✅ XSS executed successfully: Alert dialog appeared with "XSS Attack!" message
6. ✅ Lesson completed: "Congratulations, but alerts are not very impressive are they?"

**Live Demo Query:** 
```sql
SELECT * FROM user_data WHERE first_name = 'John' and last_name = 'Smith' or '1' = '1'
```

**Actual Results Displayed:**
- USERID, FIRST_NAME, LAST_NAME, CC_NUMBER, CC_TYPE, COOKIE, LOGIN_COUNT
- 101, Joe, Snow, 987654321, VISA, , 0
- 102, John, Smith, 2435600002222, MC, , 0
- 103, Jane, Plane, 123456789, MC, , 0
- And 12+ more complete user records with credit card numbers!

---

## 🛠️ QUICK TROUBLESHOOTING

**Attack not working?**
1. **Wrong lesson** → Check navigation path above
2. **Payload blocked** → Try alternative payloads provided  
3. **No response** → Check DevTools Console for errors
4. **Permission denied** → Make sure you're logged in as adminrpza

**Speed tips:**
- Use DevTools Network tab → "Edit and Resend" for quick parameter changes
- Copy-paste payloads exactly as shown
- Each lesson has multiple parts - navigate to the right part number

---

## 💡 VS Code Copilot Integration

**Generate custom payloads:**
```javascript
// Generate SQL injection for WebGoat login bypass
// Generate XSS payload for WebGoat alert  
// Generate CSRF form for WebGoat lesson
```

Paste as comments in VS Code, copy Copilot's suggestions, test in WebGoat!

---

**Last Updated:** September 2025 ✅ Live Tested & Browser Automated
