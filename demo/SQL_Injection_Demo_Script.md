# SQL Injection Demo Script for Audience
# Based on WebGoat Lesson 5a

## Part 1: Understanding the Vulnerability

### Show the Vulnerable Code Pattern
```java
// From SqlInjectionLesson5a.java - Lines 48-49
String query = "SELECT * FROM user_data WHERE first_name = 'John' and last_name = '" + accountName + "'";
Statement statement = connection.createStatement();
ResultSet results = statement.executeQuery(query);
```

**Key Problem:** Direct string concatenation with user input!

## Part 2: Live Attack Demonstration

### Step 1: Show Normal Behavior
- **Input:** `Smith`
- **Query:** `SELECT * FROM user_data WHERE first_name = 'John' AND last_name = 'Smith'`
- **Result:** Returns only John Smith's record

### Step 2: Show Basic SQL Injection
- **Input:** `Smith' OR '1'='1`
- **Query:** `SELECT * FROM user_data WHERE first_name = 'John' AND last_name = 'Smith' OR '1'='1'`
- **Result:** Returns ALL records (because '1'='1' is always true)

### Step 3: Show Data Extraction Attack
- **Input:** `Smith' UNION SELECT userid, user_name, password, cookie, cookie, cookie, userid FROM user_system_data --`
- **Query:** Original query + UNION with sensitive data table
- **Result:** Extracts passwords and sensitive data

## Part 3: Code Analysis for Audience

### The Problem (from WebGoat source):
```java
// SqlInjectionLesson5a.java:48-49
query = "SELECT * FROM user_data WHERE first_name = 'John' and last_name = '" + accountName + "'";
```

### Why It's Vulnerable:
1. **No Input Validation:** User input accepted directly
2. **String Concatenation:** Direct concatenation with SQL
3. **No Parameterization:** SQL and data mixed together
4. **No Escaping:** Special SQL characters not handled

### Attack Vectors Demonstrated:
1. **OR Injection:** `' OR '1'='1` - Bypasses WHERE conditions
2. **UNION Injection:** `' UNION SELECT ...` - Extracts additional data  
3. **Comment Injection:** `--` - Comments out rest of query
4. **Termination Injection:** `';` - Ends current query, starts new one

## Part 4: The Secure Solution

### Fixed Code Pattern:
```java
// From SqlInjectionLesson13.java - Secure version
String query = "SELECT ip FROM servers WHERE ip = ? AND hostname = ?";
PreparedStatement preparedStatement = connection.prepareStatement(query);
preparedStatement.setString(1, userInput);  // Automatically escaped!
preparedStatement.setString(2, "webgoat-prd");
ResultSet resultSet = preparedStatement.executeQuery();
```

### Why It's Secure:
1. **Parameterized Queries:** SQL structure separated from data
2. **Automatic Escaping:** Database driver handles special characters
3. **Type Safety:** Parameters have defined types
4. **No String Concatenation:** SQL template uses placeholders

## Part 5: Demo Script for Live Presentation

### WebGoat Interface Demo:
1. **Navigate to:** SQL Injection → Try It! String SQL injection
2. **Show normal input:** Enter "Smith" in dropdown
3. **Show malicious input:** Select "Smith'" and "or" and "1 = 1"
4. **Point out the result:** All user records displayed instead of just one
5. **Explain the query:** Show how the SQL was modified

### Code Comparison:
1. **Open:** `SqlInjectionLesson5a.java` (vulnerable)
2. **Show:** Line 48-49 with string concatenation
3. **Open:** `SqlInjectionLesson13.java` (secure)  
4. **Show:** Prepared statement implementation
5. **Explain:** The difference in approach

## Part 6: Key Takeaways for Audience

### What Makes Code Vulnerable:
- String concatenation with user input
- No input validation
- Direct SQL execution
- Trusting user data

### How to Prevent:
- Use Parameterized Queries (PreparedStatement)
- Validate and sanitize all inputs
- Use least privilege database accounts
- Implement proper error handling
- Regular security testing

### Real-World Impact:
- Data breaches (customer information, passwords)
- Unauthorized access to systems  
- Data modification/deletion
- Compliance violations (GDPR, PCI-DSS)
- Financial and reputational damage

## Demo Commands for Terminal

```bash
# Navigate to WebGoat directory
cd c:\Users\ropreddy\dev\WebGoat

# Show the vulnerable code
grep -n "accountName" src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java

# Show the secure code  
grep -n "PreparedStatement" src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson13.java

# Run WebGoat for live demo
java -jar target/webgoat-2025.4-SNAPSHOT.jar
```
