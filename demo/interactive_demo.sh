#!/bin/bash

# SQL Injection Interactive Demo Script
# Based on WebGoat Lesson 5a

echo "==================================================================="
echo "           SQL INJECTION VULNERABILITY DEMONSTRATION"
echo "                    Based on WebGoat Lesson 5a"
echo "==================================================================="
echo

# Function to simulate vulnerable query
show_vulnerable_query() {
    local user_input="$1"
    local base_query="SELECT * FROM user_data WHERE first_name = 'John' AND last_name = '"
    local full_query="${base_query}${user_input}'"
    
    echo "🚨 VULNERABLE CODE (String Concatenation):"
    echo "String query = \"SELECT * FROM user_data WHERE first_name = 'John' AND last_name = '\" + userInput + \"'\";"
    echo
    echo "📝 INPUT: $user_input"
    echo "🔍 RESULTING QUERY:"
    echo "   $full_query"
    echo
}

# Function to simulate secure query
show_secure_query() {
    local user_input="$1"
    
    echo "✅ SECURE CODE (Parameterized Query):"
    echo "String query = \"SELECT * FROM user_data WHERE first_name = ? AND last_name = ?\";"
    echo "preparedStatement.setString(1, \"John\");"
    echo "preparedStatement.setString(2, userInput);"
    echo
    echo "📝 INPUT: $user_input"
    echo "🔍 PARAMETERS: ['John', '$user_input']"
    echo "   (Input is automatically escaped/sanitized)"
    echo
}

# Demo 1: Normal Input
echo "DEMO 1: NORMAL USER INPUT"
echo "=========================="
user_input="Smith"
show_vulnerable_query "$user_input"
show_secure_query "$user_input"

read -p "Press Enter to continue to the attack demo..."
echo

# Demo 2: SQL Injection Attack
echo "DEMO 2: SQL INJECTION ATTACK"
echo "============================="
malicious_input="Smith' OR '1'='1"
echo "💀 MALICIOUS INPUT: $malicious_input"
echo
show_vulnerable_query "$malicious_input"
echo "⚠️  IMPACT: This returns ALL users, not just John Smith!"
echo "⚠️  The OR '1'='1' condition is always true"
echo
show_secure_query "$malicious_input"
echo "✅ IMPACT: Input is treated as literal string, attack neutralized!"
echo

read -p "Press Enter to see an advanced attack..."
echo

# Demo 3: Advanced Attack
echo "DEMO 3: ADVANCED UNION ATTACK"
echo "=============================="
union_attack="Smith' UNION SELECT userid, user_name, password, cookie, cookie, cookie, userid FROM user_system_data --"
echo "💀 UNION ATTACK INPUT:"
echo "   $union_attack"
echo
show_vulnerable_query "$union_attack"
echo "⚠️  IMPACT: This could extract sensitive data from other tables!"
echo "⚠️  The -- comments out the rest of the original query"
echo

read -p "Press Enter to see the WebGoat file locations..."
echo

# Show file locations
echo "WEBGOAT SOURCE CODE LOCATIONS"
echo "=============================="
echo "📁 Vulnerable Code:"
echo "   src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java"
echo "   Line 48-49: String concatenation vulnerability"
echo
echo "📁 Secure Code:"
echo "   src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson13.java"  
echo "   Lines 50-53: PreparedStatement implementation"
echo
echo "📁 WebGoat Application:"
echo "   http://localhost:8080/WebGoat"
echo "   Navigate to: SQL Injection → Try It! String SQL injection"
echo

echo "==================================================================="
echo "                        DEMO COMPLETE"
echo "==================================================================="
echo "🎯 Key Takeaways:"
echo "   1. Never use string concatenation for SQL queries"
echo "   2. Always use parameterized queries (PreparedStatement)"
echo "   3. Validate and sanitize all user inputs"  
echo "   4. Test your applications for SQL injection vulnerabilities"
echo "==================================================================="