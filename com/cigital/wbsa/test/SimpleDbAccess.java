/**
 * Test cases for Secure Assist plug-in.
 * These focus on some of the simple patterns that should be easy to detect.
 */
package com.cigital.wbsa.test;

import java.sql.*;

import javax.servlet.http.HttpServletRequest;

public class SimpleDbAccess {
	private final String queryStart = "SELECT Lname FROM Customers WHERE Snum = ";
	private String connString = "jdbc:msql://200.210.220.1:1114/Demo";
	private String queryGetAllCustomers;

	public SimpleDbAccess() {
		queryGetAllCustomers = "select * from Customers";
	}
	
	public void simpleSqlQuery() {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
			// This line should fire rule (dangerous call).
           rs = stmt.executeQuery(
            		"SELECT Lname FROM Customers WHERE Snum = 2001");
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
			// This line should fire rule (should be in finally block).
            conn.close();
        } catch (Exception e) {
        	/**
        	 * Catching a broad exception can be dangerous.
        	 */
            System.err.println(e.getMessage());
        }
	}

	/**
	 * This method verifies we can distinguish methods based on signature.
	 * 
	 * @param param1
	 */
	public void simpleSqlQuery(String param1) {
        try {
            Connection conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
			// This line should fire rule (dangerous call).
            rs = stmt.executeQuery(
            		"SELECT Lname FROM Customers WHERE Lname = '"
            		+ param1 + "'");
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
			// This line should fire rule (should be in finally block).
            conn.close();
        } catch (SQLException e) {
            System.err.println(e.getMessage());
        }
	}

	public void simpleBadQuery(String param1) throws SQLException{
		Connection conn = null;
        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
			// This line should fire rule (dangerous call).
            rs = stmt.executeQuery(
            		"SELECT Lname FROM Customers WHERE Lname = '"
            		+ param1 + "'");
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}

	public void simpleBadQuery2(String param1) throws SQLException{
		Connection conn = null;
        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
            String query = "SELECT Lname FROM Customers WHERE Lname = '"
        		+ param1 + "'";
			// This line should fire rule (dangerous call).
            rs = stmt.executeQuery(query);
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}
	
	public void simpleBadQuery3(String param1) throws SQLException{
		Connection conn = null;
        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
            String query = queryStart + param1;
			// This line should fire rule (dangerous call).
            rs = stmt.executeQuery(query);
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}
	
	public boolean simpleSafeQuery(int searchID) throws SQLException{
		Connection conn = null;
        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
			// This line should fire rule (dangerous call).
            rs = stmt.executeQuery(
            		"SELECT Lname FROM Customers WHERE id = "
            		+ Integer.toString(searchID));
            return rs.next();
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}
	
	public boolean simpleSafeQuery2() throws SQLException{
		Connection conn = null;
        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;

            String query = queryStart + "2001";
			// This line should fire rule (dangerous call).
            // No other issue here since queryStart is final string concat with string literal
            rs = stmt.executeQuery(query);
            return rs.next();
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}
	
	public boolean simpleSafeQuery3() throws SQLException{
		Connection conn = null;
        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;

			// This line should fire rule (dangerous call).
            // No other issue here since queryStart is final string concat with string literal
            rs = stmt.executeQuery(queryStart + "2001");
            return rs.next();
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}
	
	public void dumpAllCustomers() {
        try {
        	Connection conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
			// This line should fire rule (dangerous call).
            rs = stmt.executeQuery(queryGetAllCustomers);
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        /**
         * Not calling conn.close() is a bad practice.
         */
	}
	
	public void simpleSqlQueryWithTrustedVariable() {
		Connection conn = null;
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            conn = DriverManager.getConnection(url,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
            String query = 
        		"SELECT Lname FROM Customers WHERE Snum = 2001";
 
			// This line should fire rule (dangerous call).
            // No other issue here since Query should be trusted.
            rs = stmt.executeQuery(query);
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
	}
	
	public void simpleSqlQueryWithTrustedVariable2() {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
            String query = 
        		"SELECT Lname FROM Customers WHERE Snum =";
            String sNum = "2001";
            query += sNum;
 
			// This line should fire rule (dangerous call).
            // No other issue here since query is built using string literals.
            rs = stmt.executeQuery(query);
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
	}
	
	public void simpleSqlQueryWithTrustedVariable3() {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
            String query = 
        		"SELECT Lname FROM Customers WHERE Snum =";
            String sNum = "2001";
            query = query + sNum;
 
			// This line should fire rule (dangerous call).
            // No other issue here since query is built using string literals.
            rs = stmt.executeQuery(query);
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
    } catch (Exception e) {
        System.err.println(e.getMessage());
        }
	}
	
	public void simpleSqlQueryWithUnTrustedVariable(HttpServletRequest request) {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
            String query = 
        		"SELECT Lname FROM Customers WHERE Snum = ";
			// This line should fire rule (dangerous call).
            query = query + request.getParameter("Snum");
 
			// This line should fire rule (dangerous call).
            // Because query is built from untrusted method call, it should be High impact.
            rs = stmt.executeQuery(query);
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
	}
	
	public void simpleSqlQueryWithUnTrustedVariable2(HttpServletRequest request) {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
            String query = 
        		"SELECT Lname FROM Customers WHERE Snum = ";
 
			// This line should fire rule (dangerous call).
            // Because parameter is built from untrusted method call, it should be High impact.
            rs = stmt.executeQuery(query + request.getParameter("Snum"));
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
	}
	
	public void simpleSqlQueryWithUnTrustedVariable3(HttpServletRequest request) {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
			// This line should fire rule (dangerous call).
            // Because parameter is built from untrusted method call, it should be High impact.
            rs = stmt.executeQuery("SELECT Lname FROM Customers WHERE Snum = " + request.getParameter("Snum"));
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
	}

}
