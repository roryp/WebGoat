/**
 * SQL Injection Demonstration for Audience
 * Based on WebGoat Lesson 5a
 */
public class SQLInjectionDemo {
    
    /**
     * VULNERABLE VERSION - Don't use this in production!
     * This demonstrates the security flaw
     */
    public void vulnerableQuery(String userInput) {
        // ❌ DANGEROUS: Direct string concatenation
        String query = "SELECT * FROM user_data WHERE first_name = 'John' AND last_name = '" + userInput + "'";
        
        System.out.println("🚨 VULNERABLE QUERY:");
        System.out.println(query);
        System.out.println();
        
        // This would execute the malicious query!
        // statement.executeQuery(query); 
    }
    
    /**
     * SECURE VERSION - Use this instead!
     * This demonstrates the proper way to handle user input
     */
    public void secureQuery(String userInput) {
        // ✅ SAFE: Using PreparedStatement with parameterized queries
        String query = "SELECT * FROM user_data WHERE first_name = ? AND last_name = ?";
        
        System.out.println("✅ SECURE QUERY:");
        System.out.println(query);
        System.out.println("Parameters: ['John', '" + userInput + "']");
        System.out.println();
        
        // PreparedStatement prep = connection.prepareStatement(query);
        // prep.setString(1, "John");
        // prep.setString(2, userInput);  // Automatically escaped!
        // ResultSet results = prep.executeQuery();
    }
    
    /**
     * Demo the difference between vulnerable and secure approaches
     */
    public static void main(String[] args) {
        SQLInjectionDemo demo = new SQLInjectionDemo();
        
        System.out.println("=== SQL INJECTION DEMONSTRATION ===\n");
        
        // Normal input
        System.out.println("1. NORMAL INPUT: 'Smith'");
        demo.vulnerableQuery("Smith");
        demo.secureQuery("Smith");
        
        // Malicious input
        System.out.println("2. MALICIOUS INPUT: 'Smith' OR '1'='1'");
        demo.vulnerableQuery("Smith' OR '1'='1");
        demo.secureQuery("Smith' OR '1'='1");
        
        // Advanced attack
        System.out.println("3. ADVANCED ATTACK: 'Smith'; DROP TABLE users; --'");
        demo.vulnerableQuery("Smith'; DROP TABLE users; --");
        demo.secureQuery("Smith'; DROP TABLE users; --");
    }
}
