package util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * UNIT V: Accessing Databases with JDBC
 * Singleton utility class managing database connections to MySQL.
 */
public class DBConnection {

    private static String getEnvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value == null || value.trim().isEmpty()) ? defaultValue : value.trim();
    }

    // Database credentials can be overridden via environment variables
    // (DB_URL, DB_USER, DB_PASSWORD) for local or hosted MySQL setups.
    private static final String URL = getEnvOrDefault(
            "DB_URL",
            "jdbc:mysql://localhost:3306/job_tracker?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
    );
    private static final String USER = getEnvOrDefault("DB_USER", "root");
    private static final String PASSWORD = getEnvOrDefault("DB_PASSWORD", "");

    // Static block to register MySQL driver class
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new ExceptionInInitializerError(
                    "MySQL JDBC Driver is missing from the runtime classpath. Add mysql-connector-j to the classpath.");
        }
    }

    /**
     * Returns a new connection to the job_tracker database.
     * @return active java.sql.Connection
     * @throws SQLException on connection failure
     */
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    /**
     * Closes the connection safely, used in 'finally' blocks to prevent resource leaks.
     * @param con Connection to close
     */
    public static void closeConnection(Connection con) {
        if (con != null) {
            try {
                con.close();
            } catch (SQLException e) {
                System.out.println("Error closing connection: " + e.getMessage());
            }
        }
    }
}
