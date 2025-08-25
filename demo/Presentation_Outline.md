# SQL Injection Code Demo - Presentation Outline

## Slide 1: The Problem - Vulnerable Code
```java
// From WebGoat SqlInjectionLesson5a.java (Line 48-49)
String query = "SELECT * FROM user_data WHERE first_name = 'John' and last_name = '" 
               + accountName + "'";
Statement statement = connection.createStatement();
ResultSet results = statement.executeQuery(query);
```

**What's Wrong:**
- Direct string concatenation with user input
- No validation or sanitization
- User controls part of the SQL query structure

---

## Slide 2: Normal vs Malicious Input

### Normal Input: "Smith"
```sql
SELECT * FROM user_data WHERE first_name = 'John' and last_name = 'Smith'
```
**Result:** Returns John Smith's record

### Malicious Input: "Smith' OR '1'='1"
```sql
SELECT * FROM user_data WHERE first_name = 'John' and last_name = 'Smith' OR '1'='1'
```
**Result:** Returns ALL records (because '1'='1' is always true)

---

## Slide 3: Advanced Attack - Data Extraction

### Input: "Smith' UNION SELECT userid, user_name, password, cookie, cookie, cookie, userid FROM user_system_data --"

```sql
SELECT * FROM user_data WHERE first_name = 'John' and last_name = 'Smith' 
UNION SELECT userid, user_name, password, cookie, cookie, cookie, userid 
FROM user_system_data --'
```

**Result:** Extracts sensitive data from other tables
- The `--` comments out the trailing quote
- UNION adds data from another table
- Reveals passwords and sensitive information

---

## Slide 4: The Solution - Secure Code
```java
// From WebGoat SqlInjectionLesson13.java (Lines 50-53)
String query = "SELECT ip FROM servers WHERE ip = ? AND hostname = ?";
PreparedStatement preparedStatement = connection.prepareStatement(query);
preparedStatement.setString(1, userInput);  // Automatically escaped!
preparedStatement.setString(2, "webgoat-prd");
ResultSet resultSet = preparedStatement.executeQuery();
```

**Why It's Secure:**
- Parameterized queries separate SQL structure from data
- Database driver automatically escapes special characters
- User input cannot alter the query structure

---

## Slide 5: Live Demo Steps

1. **Show WebGoat Interface**
   - Navigate to SQL Injection lesson
   - Demonstrate normal input
   - Show attack payload
   - Display results

2. **Show Source Code**
   - Open vulnerable file: `SqlInjectionLesson5a.java`
   - Highlight line 48-49
   - Open secure file: `SqlInjectionLesson13.java`
   - Compare approaches

3. **Explain Impact**
   - Data breaches
   - Unauthorized access
   - Data manipulation
   - Compliance violations

---

## Slide 6: Prevention Checklist

✅ **Use Parameterized Queries**
- PreparedStatement in Java
- Parameterized queries in .NET
- Prepared statements in PHP

✅ **Input Validation**
- Validate data type, length, format
- Use allowlists, not blocklists
- Sanitize special characters

✅ **Least Privilege**
- Database accounts with minimal permissions
- Separate accounts for different functions
- Regular permission audits

✅ **Security Testing**
- Static code analysis
- Dynamic testing tools
- Regular penetration testing

---

## Code Files for Reference

### Vulnerable Examples:
- `SqlInjectionLesson2.java` - Basic string injection
- `SqlInjectionLesson5a.java` - Current lesson
- `SqlInjectionLesson8.java` - Confidentiality attack
- `SqlInjectionLesson9.java` - Integrity attack

### Secure Examples:
- `SqlInjectionLesson13.java` - Prepared statements
- `SqlInjectionLesson10b.java` - Code validation
- Mitigation package - Various secure patterns

### Demo Commands:
```bash
# Run interactive demo
./demo/interactive_demo.ps1

# Start WebGoat
java -jar target/webgoat-2025.4-SNAPSHOT.jar

# Access application
http://localhost:8080/WebGoat
```
