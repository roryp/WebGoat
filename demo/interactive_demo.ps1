# SQL Injection Interactive Demo Script (PowerShell)
# Based on WebGoat Lesson 5a

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "           SQL INJECTION VULNERABILITY DEMONSTRATION" -ForegroundColor Yellow
Write-Host "                    Based on WebGoat Lesson 5a" -ForegroundColor Yellow
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host

# Function to simulate vulnerable query
function Show-VulnerableQuery {
    param([string]$userInput)
    
    $baseQuery = "SELECT * FROM user_data WHERE first_name = 'John' AND last_name = '"
    $fullQuery = "${baseQuery}${userInput}'"
    
    Write-Host "🚨 VULNERABLE CODE (String Concatenation):" -ForegroundColor Red
    Write-Host "String query = `"SELECT * FROM user_data WHERE first_name = 'John' AND last_name = '`" + userInput + `"'`";" -ForegroundColor Gray
    Write-Host
    Write-Host "📝 INPUT: $userInput" -ForegroundColor White
    Write-Host "🔍 RESULTING QUERY:" -ForegroundColor Yellow
    Write-Host "   $fullQuery" -ForegroundColor Gray
    Write-Host
}

# Function to simulate secure query
function Show-SecureQuery {
    param([string]$userInput)
    
    Write-Host "✅ SECURE CODE (Parameterized Query):" -ForegroundColor Green
    Write-Host "String query = `"SELECT * FROM user_data WHERE first_name = ? AND last_name = ?`";" -ForegroundColor Gray
    Write-Host "preparedStatement.setString(1, `"John`");" -ForegroundColor Gray
    Write-Host "preparedStatement.setString(2, userInput);" -ForegroundColor Gray
    Write-Host
    Write-Host "📝 INPUT: $userInput" -ForegroundColor White
    Write-Host "🔍 PARAMETERS: ['John', '$userInput']" -ForegroundColor Yellow
    Write-Host "   (Input is automatically escaped/sanitized)" -ForegroundColor Green
    Write-Host
}

# Demo 1: Normal Input
Write-Host "DEMO 1: NORMAL USER INPUT" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
$userInput = "Smith"
Show-VulnerableQuery $userInput
Show-SecureQuery $userInput

Read-Host "Press Enter to continue to the attack demo"
Write-Host

# Demo 2: SQL Injection Attack
Write-Host "DEMO 2: SQL INJECTION ATTACK" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
$maliciousInput = "Smith' OR '1'='1"
Write-Host "💀 MALICIOUS INPUT: $maliciousInput" -ForegroundColor Red
Write-Host
Show-VulnerableQuery $maliciousInput
Write-Host "⚠️  IMPACT: This returns ALL users, not just John Smith!" -ForegroundColor Red
Write-Host "⚠️  The OR '1'='1' condition is always true" -ForegroundColor Red
Write-Host
Show-SecureQuery $maliciousInput
Write-Host "✅ IMPACT: Input is treated as literal string, attack neutralized!" -ForegroundColor Green
Write-Host

Read-Host "Press Enter to see an advanced attack"
Write-Host

# Demo 3: Advanced Attack
Write-Host "DEMO 3: ADVANCED UNION ATTACK" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
$unionAttack = "Smith' UNION SELECT userid, user_name, password, cookie, cookie, cookie, userid FROM user_system_data --"
Write-Host "💀 UNION ATTACK INPUT:" -ForegroundColor Red
Write-Host "   $unionAttack" -ForegroundColor Gray
Write-Host
Show-VulnerableQuery $unionAttack
Write-Host "⚠️  IMPACT: This could extract sensitive data from other tables!" -ForegroundColor Red
Write-Host "⚠️  The -- comments out the rest of the original query" -ForegroundColor Red
Write-Host

Read-Host "Press Enter to see the WebGoat file locations"
Write-Host

# Show file locations
Write-Host "WEBGOAT SOURCE CODE LOCATIONS" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "📁 Vulnerable Code:" -ForegroundColor Yellow
Write-Host "   src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java" -ForegroundColor Gray
Write-Host "   Line 48-49: String concatenation vulnerability" -ForegroundColor Red
Write-Host
Write-Host "📁 Secure Code:" -ForegroundColor Yellow
Write-Host "   src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson13.java" -ForegroundColor Gray
Write-Host "   Lines 50-53: PreparedStatement implementation" -ForegroundColor Green
Write-Host
Write-Host "📁 WebGoat Application:" -ForegroundColor Yellow
Write-Host "   http://localhost:8080/WebGoat" -ForegroundColor Gray
Write-Host "   Navigate to: SQL Injection → Try It! String SQL injection" -ForegroundColor Gray
Write-Host

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "                        DEMO COMPLETE" -ForegroundColor Yellow
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "🎯 Key Takeaways:" -ForegroundColor Green
Write-Host "   1. Never use string concatenation for SQL queries" -ForegroundColor White
Write-Host "   2. Always use parameterized queries (PreparedStatement)" -ForegroundColor White
Write-Host "   3. Validate and sanitize all user inputs" -ForegroundColor White
Write-Host "   4. Test your applications for SQL injection vulnerabilities" -ForegroundColor White
Write-Host "===================================================================" -ForegroundColor Cyan