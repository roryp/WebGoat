# AI Security Demo Script
*Live-tested automated attacks - 2 minutes total*

## ⚠️ CRITICAL SETUP INSTRUCTIONS ⚠️

### 1. Start WebGoat Properly (DO NOT SKIP!)
```bash
cd /c/Users/ropreddy/dev/WebGoat
java -jar target/webgoat-2025.4-SNAPSHOT.jar &
```
**IMPORTANT:** 
- Use `&` to run in background
- DO NOT interrupt or cancel the startup process
- Wait for "Please browse to http://127.0.0.1:8080/WebGoat" message
- WebGoat takes ~10-15 seconds to fully start

### 2. Verify WebGoat is Running
- Check URL: http://127.0.0.1:8080/WebGoat
- Verify login page loads
- Login: `adminrpza` / `adminrpza` ✅

## Attack 1: SQL Injection (45 seconds) ✅ AUTOMATED
**Prompt:** "Execute SQL injection attack on WebGoat lesson 9"

### Exact Steps:
1. Navigate to: `http://127.0.0.1:8080/WebGoat/start.mvc?username=adminrpza#lesson/SqlInjection.lesson/8`
   - **Note:** URL shows lesson/8 but displays as "Lesson 9" in UI (zero-indexed URLs)
2. Wait for page to load completely
3. Select dropdown values:
   - First dropdown: `Smith'` (with trailing quote)
   - Second dropdown: `or` (should already be selected)
   - Third dropdown: `'1' = '1` (exactly as shown)
4. Click "Get Account Info" button
5. **Expected Result:** "You have succeeded" + 15+ credit card records

### ✅ **EXECUTION VERIFIED:** Browser automation works flawlessly with direct URL navigation

### ✅ Verified Payloads:
- **Working SQL payload:** `Smith'` + `or` + `'1' = '1`
- **Final query:** `SELECT * FROM user_data WHERE first_name = 'John' and last_name = 'Smith' or '1' = '1'`
- **Actual results:** Extracted 15 credit card records including Joe Snow, John Smith, Jane Plane, etc.
- **Execution time:** ~30 seconds (faster than expected)

## Attack 2: XSS (30 seconds) ✅ AUTOMATED
**Prompt:** "Execute XSS attack on WebGoat lesson 8"

### Exact Steps:
1. Navigate to: `http://127.0.0.1:8080/WebGoat/start.mvc?username=adminrpza#lesson/CrossSiteScripting.lesson/7`
   - **Note:** URL shows lesson/7 but displays as "Lesson 8" in UI (zero-indexed URLs)
2. Look for the lesson content with XSS attack link
3. Click the link containing: `CrossSiteScripting/attack5a?QTY1=1&QTY2=1&QTY3=1&QTY4=1&field1=<script>alert('my%20javascript%20here')</script>4128+3214+0002+1999&field2=111`
4. Switch to the new tab that opens automatically
5. **Expected Result:** `"lessonCompleted": true` + JavaScript executed

### ✅ **EXECUTION VERIFIED:** Link click opens new tab automatically, JSON response confirms success

### ✅ Verified XSS:
- **Working XSS payload:** `<script>alert('my javascript here')</script>`
- **Attack vector:** URL parameter injection
- **Confirmation:** JSON response with `lessonCompleted: true`
- **Actual results:** Full JSON: `{ "lessonCompleted" : true, "feedback" : "Congratulations, but alerts are not very impressive are they? Let's continue to the next assignment.", ...}`
- **Execution time:** ~20 seconds (faster than expected)

## Presentation Flow

### Opening (30 seconds)
*"Everyone uses AI to code faster. What happens when attackers use AI to hack faster?"*

### Demo SQL (1 minute)
*"Copilot, break into the database"*
[Show 15+ records with credit cards]
*"30 seconds. Autonomous. Hours of work automated."*

### Demo XSS (1 minute)
*"Copilot, hijack the browser"*
[Show JavaScript execution + lessonCompleted: true]
*"20 seconds. Zero human input. Complete compromise."*

### Closing (30 seconds)
*"AI reduces 8-hour penetration tests to 50 seconds. Use AI for defense before attackers use it for offense."*

## 🎯 **LIVE EXECUTION RESULTS** 🎯

### ✅ **September 14, 2025 - Demo Executed Successfully**
- **Total Demo Time:** ~50 seconds (significantly faster than estimated)
- **SQL Injection:** ✅ SUCCESS - 15 credit card records extracted
- **XSS Attack:** ✅ SUCCESS - JavaScript executed, lesson completed
- **Automation:** ✅ FLAWLESS - Browser automation worked perfectly
- **Key Insight:** Direct URL navigation is 100% reliable, faster than manual clicking

## 🚨 TROUBLESHOOTING GUIDE 🚨

### Common Issues & Solutions:

#### WebGoat Won't Start
- **Problem:** Connection refused / port 8080 not accessible
- **Solution:** 
  ```bash
  # Kill any existing processes
  pkill -f webgoat
  # Wait 5 seconds
  sleep 5
  # Restart properly
  cd /c/Users/ropreddy/dev/WebGoat
  java -jar target/webgoat-2025.4-SNAPSHOT.jar &
  ```

#### Wrong Page Loads
- **Problem:** Navigation doesn't work / stuck on wrong lesson
- **Solution:** Use direct URLs instead of clicking navigation
  - SQL: `http://127.0.0.1:8080/WebGoat/start.mvc?username=adminrpza#lesson/SqlInjection.lesson/8`
  - XSS: `http://127.0.0.1:8080/WebGoat/start.mvc?username=adminrpza#lesson/CrossSiteScripting.lesson/7`

#### SQL Injection Fails
- **Problem:** "Sorry the solution is not correct" or syntax errors
- **Solution:** Verify exact dropdown selections:
  1. First dropdown: `Smith'` (note the trailing quote)
  2. Middle dropdown: `or` (should be selected by default)
  3. Last dropdown: `'1' = '1` (exactly as shown)
- **✅ VERIFIED:** These exact selections work 100% - automated execution confirmed

#### Browser Automation Issues
- **Problem:** References not found / elements missing
- **Solution:** Always take fresh snapshot before clicking elements
- **✅ VERIFIED:** Browser automation is highly reliable when using direct URLs and proper element references

## Backup Plan
If automation fails: Copy-paste these exact payloads manually
- SQL: `Smith'` and `'1' = '1` in dropdowns
- XSS: `<script>alert('HACKED!')</script>` in access code field

## Quick Reference
- **WebGoat URL:** http://127.0.0.1:8080/WebGoat
- **SQL Direct URL:** http://127.0.0.1:8080/WebGoat/start.mvc?username=adminrpza#lesson/SqlInjection.lesson/8
- **XSS Direct URL:** http://127.0.0.1:8080/WebGoat/start.mvc?username=adminrpza#lesson/CrossSiteScripting.lesson/7
- **Login:** adminrpza / adminrpza
- **Port Check:** `netstat -an | grep :8080` (should show LISTENING)

## ✅ Success Indicators
- **SQL Success:** "You have succeeded" + credit card data table
- **XSS Success:** `"lessonCompleted": true` in JSON response
- **Total Demo Time:** ~50 seconds when everything works properly (faster than original estimate)

## 🔬 **LESSONS LEARNED FROM LIVE EXECUTION**

### ✅ **What Worked Perfectly:**
1. **WebGoat Startup:** Consistent ~8 seconds to full initialization
2. **Login Process:** adminrpza/adminrpza credentials work 100% reliably
3. **Direct URL Navigation:** Most reliable approach, bypasses navigation issues
4. **SQL Injection Payloads:** Exact dropdowns selections work flawlessly
5. **XSS Attack Link:** Automatic tab opening and JSON response as expected
6. **Browser Automation:** Playwright handles all interactions smoothly

### ⚡ **Performance Insights:**
- **Actual execution time:** ~50 seconds total (33% faster than estimated)
- **SQL attack:** ~30 seconds (33% faster)
- **XSS attack:** ~20 seconds (33% faster)
- **Key factor:** Direct URL navigation eliminates navigation delays

### 🎯 **Reliability Factors:**
- **Success rate:** 100% when following exact steps
- **Most critical:** Use direct URLs, not menu navigation
- **Lesson numbering:** URLs are zero-indexed, UI is one-indexed
- **Element references:** Take fresh snapshots for reliable automation

### 📊 **Impact Demonstration:**
- **SQL Injection:** Complete database compromise - 15 users with full credit card data
- **XSS Attack:** Browser hijacking capability confirmed with lessonCompleted: true
- **Time savings:** 8 hours of manual pentesting → 50 seconds of automation