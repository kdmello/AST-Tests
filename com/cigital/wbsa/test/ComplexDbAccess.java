/**
 * Test cases for Secure Assist plug-in.
 * These focus on complex interactions with a DB that are harder to discover.
 */
package com.cigital.wbsa.test;

import java.sql.*;
import javax.servlet.http.*;

public class ComplexDbAccess {
	private String connString = "jdbc:msql://200.210.220.1:1114/Demo";
	private String queryGetAllCustomers;
	private static final String finalPrivateQuery = "select * from Customers";
	public static final String finalPublicQuery = "select * from Customers";

	public ComplexDbAccess() {
		queryGetAllCustomers = "select * from Customers";
	}

	private ResultSet executeQuery(String query) throws SQLException {
		Connection conn = null;

        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
 
			// This line should fire rule (dangerous call).
            return stmt.executeQuery(query);
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}

	public ResultSet getAllCustomers() throws SQLException {
		// This line should not fire rule (literal string used).
		return executeQuery(queryGetAllCustomers);
	}

	private void executeQueryPS(String query) throws SQLException {
		Connection conn = null;

        try {
            conn = DriverManager.getConnection(connString,"","");
			// This line should fire rule (dangerous call).
            // Calls with tainted data should fire rule with High Impact.
            PreparedStatement stmt = conn.prepareStatement(query);

            // This line should only fire rule when "query" is tainted.
            stmt.execute();
            
			// This line should fire rule (dangerous call).
            // Calls with tainted data should fire rule with High Impact.
            stmt.execute(query);
            
			// This line should fire rule (dangerous call).
            // Calls with tainted data should fire rule with High Impact.
            stmt.executeQuery(query);
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}

	public void getAllCustomersPS() throws SQLException {
		// This line should not fire rule (literal string used).
		executeQueryPS(queryGetAllCustomers);
	}

	public void getAllCustomersPSWithTaint(HttpServletRequest request) throws SQLException {
		// This line should fire rule.
		executeQueryPS(queryGetAllCustomers
				+ " and user = '" + request.getParameter("username") + "'");
	}

	public boolean validCredentials(String username, String password)
	throws SQLException {
		Connection conn = null;

        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
 
			// This line should fire rule (dangerous call).
            // Calls with tainted data should fire rule with High Impact.
            ResultSet rs = stmt.executeQuery(
            		"SELECT Lname FROM Customers WHERE username = '"
            		+ username + "' and password = '" + password + "'");
            return rs.next();
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}
	
	public boolean checkCredsTest1() throws SQLException {
		// This line should not fire rule (literal string used).
		return validCredentials("admin", "password");
	}
	
	public boolean checkCredsTest2(String username, String password) {
		try {
            // This line should only fire rule when parameters are tainted.
			return validCredentials(username, password);
		}
		catch (Exception e) {
			return false;
		}
	}
	
	public boolean checkCredsTest3(String username, String password) {
		try {
            // This line should only fire rule when parameters are tainted.
			if(validCredentials(username, password))
				return true;
			
			// This line should not fire rule (literal string used).
			return validCredentials("admin", "password");
		}
		catch (Exception e) {
			return false;
		}
	}
	
	public boolean checkUseOfFinalVariables(HttpServletRequest request) {
		try {
			// This line should not fire rule (literal string used).
			executeQuery(finalPrivateQuery);
			executeQuery(finalPrivateQuery + " where seqnum=1");
			executeQuery(finalPrivateQuery + " where seqnum="
					+ Integer.parseInt(request.getParameter("ID")));
			executeQuery(finalPublicQuery);
			executeQuery(finalPublicQuery + " where seqnum=1");
			executeQuery(finalPublicQuery + " where seqnum="
					+ Integer.parseInt(request.getParameter("ID")));

			// This line should fire rule (SQL Injection).
			executeQuery(finalPrivateQuery + " where lastname='"
					+ request.getParameter("lname") + "'");
			// This line should fire rule (SQL Injection).
			executeQuery(finalPublicQuery + " where lastname='"
					+ request.getParameter("lname") + "'");

			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	public void checkTaintPropogation1(HttpServletRequest request) {
		try {
			// This line should fire rule (dangerous call).
			String username = request.getParameter("username");
			// This line should fire rule (dangerous call).
			String password = request.getParameter("password");
			
			// This line should fire rule (SQL Injection).
			validCredentials(username, password);
			
			// This line should fire rule (SQL Injection).
			checkCredsTest2(username, password);
			
			// This line should fire rule for only one path through checkCredsTest3 (SQL Injection).
			checkCredsTest3(username, password);

		} catch (Exception e) {
			// TODO
		}
	}

	public void checkTaintPropogation2(HttpServletRequest request) {
		try {
			// This line should fire rule (dangerous call).
			String username = request.getParameter("username");
			// This line should fire rule (dangerous call).
			String password = request.getParameter("password");
			
			// This line should fire rule (SQL Injection).
			validCredentials(username, password);
			
			username = "";
			password = "";
			// This line should not fire rule (literal string used).
			validCredentials(username, password);
			
			// This line should fire rule (dangerous call).
			username = request.getParameter("username");
			// This line should fire rule (dangerous call).
			password = request.getParameter("password");
			// This line should fire rule (SQL Injection).
			validCredentials(username, password);

		} catch (Exception e) {
			// TODO
		}
	}

	public void checkTaintPropogation3(HttpServletRequest request) {
		try {
			// This line should fire rule (dangerous call).
			String username = request.getParameter("username");
			// This line should fire rule (dangerous call).
			String password = request.getParameter("password");
			
			if (username.length() < 10) {
				// This line should fire rule (SQL Injection).
				validCredentials(username, password);
			} else {
				username = "";
				password = "";
				// This line should not fire rule (literal string used).
				validCredentials(username, password);
			}
		} catch (Exception e) {
			// TODO
		}
	}

}
