package com.example;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.commons.text.StringEscapeUtils;

public class OwaspExamples {
    private static final Logger logger = LogManager.getLogger(OwaspExamples.class);

    public static void main(String[] args) {
        // SQL Injection mitigation example
        Connection connection = null; // Assume you have a valid connection
        try {
            String username = "admin"; // Example user input
            // Vulnerable SQL query
            String queryVulnerable = "SELECT * FROM users WHERE username = '" + username + "'";
            System.out.println("Vulnerable SQL query: " + queryVulnerable);

            // Secure SQL query using parameterized PreparedStatement
            String query = "SELECT * FROM users WHERE username = ?";
            PreparedStatement pstmt = connection.prepareStatement(query);
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            System.out.println("Secure SQL query executed.");
        } catch (SQLException e) {
            e.printStackTrace();
        }

        // Broken Authentication and Session Management
        // Secure usage of HttpOnly and Secure flags for cookies
        HttpSession session = null; // Example, assuming you are in a servlet context
        Cookie cookie = new Cookie("sessionId", session.getId());
        cookie.setSecure(true);  // Secure flag
        cookie.setHttpOnly(true); // HttpOnly flag
        System.out.println("Secure cookie set: HttpOnly and Secure flags applied.");

        // Cross-Site Scripting (XSS) prevention
        String userInput = "<script>alert('XSS!')</script>";
        String escapedUserInput = StringEscapeUtils.escapeHtml4(userInput);
        System.out.println("Escaped User Input: " + escapedUserInput);

        // Insecure Direct Object Reference Mitigation Example
        User user = new User(); // Assume you have a User object
        if (user != null && user.hasRole("admin")) {
            user.setRole("admin");
            System.out.println("Admin role set securely.");
        }

        // Sensitive Data Exposure mitigation
        String creditCardNumber = "1234567812345678";
        System.out.println("Secure Credit Card Display: " + creditCardNumber.substring(0, 4) + "****" + creditCardNumber.substring(12));
    }

    // Mock User class for demonstration purposes
    static class User {
        private String role;

        public boolean hasRole(String role) {
            // Check user role
            return "admin".equals(role);
        }

        public void setRole(String role) {
            this.role = role;
        }
    }
}

