/**
 * Test cases for Secure Assist plug-in.
 * These combine as many issues as possible into a single file so
 * there is no need to do "deep scanning".
 */
package com.cigital.wbsa.test;

import java.io.IOException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Random;

import javax.servlet.http.*;

public class AllInOne {

	private String connString = "jdbc:msql://200.210.220.1:1114/Demo";
	private String queryGetAllCustomers;
	private static final String finalPrivateQuery = "select * from Customers";
	public static final String finalPublicQuery = "select * from Customers";
	private Random unsafeRandom = new Random();
	static public SecureRandom safeRandom = new SecureRandom();
	private String myString;
	private int myInt = -9999;
	static private boolean myStatus = false;

	public AllInOne() {
		queryGetAllCustomers = "select * from Customers";
		myString = "initial value";
		myStatus = true;
	}
	
	public boolean returnStatus() {
		return myStatus;
	}
	
	public int returnInt() {
		return myInt;
	}

	public boolean checkLogin(HttpServletRequest request) {
		try {
			/**
			 * Should be the start of a SQL Injection issue.
			 */
			String username = request.getParameter("username");
			String password = request.getParameter("password");
			return validCredentials(username, password);
		}
		catch (Exception e) {
			return false;
		}
	}
	
	public void trustViolation(
			HttpServletRequest request, HttpServletResponse response)
	throws IOException {
		String newPage = request.getParameter("newPage");
		/**
		 * Basic example of URL manipulation with user data.
		 */
		response.sendRedirect(newPage);
	}
	
	private String getNewPage(HttpServletRequest request) {
		return request.getParameter("newPage");
	}
	
	private String getNewPageSafe(HttpServletRequest request) {
		String newPage = request.getParameter("newPage");
		if (newPage.equals("redirect1"))
			return "redirect1";
		if (newPage.equals("redirect2"))
			return "redirect2";
		return "";
	}
	
	public void trustViolation2(
			HttpServletRequest request, HttpServletResponse response)
	throws IOException {
		/**
		 * An example of URL manipulation with user data.
		 */
		response.sendRedirect(getNewPage(request));
	}
	
	public void noTrustViolation1(
			HttpServletRequest request, HttpServletResponse response)
	throws IOException {
		/**
		 * This is safe.
		 */
		response.sendRedirect(getNewPageSafe(request));
	}
	
	public void noTrustViolation2(
			HttpServletRequest request, HttpServletResponse response)
	throws IOException {
		String newPage = request.getParameter("newPage");
		if (newPage.equals("redirect1"))
			newPage = "redirect1";
		else if (newPage.equals("redirect2"))
			newPage = "redirect2";
		else
			newPage = "";
		/**
		 * This is safe.
		 */
		response.sendRedirect(newPage);
	}
	
	public void simpleSqlQuery() {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
            rs = stmt.executeQuery(
            		"SELECT Lname FROM Customers WHERE Snum = 2001");
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
            /**
             * The following line should be in a "finally" block.
             */
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
 
            /**
             * If "param1" is tainted, we have SQL Injection.
             */
            rs = stmt.executeQuery(
            		"SELECT Lname FROM Customers WHERE Lname = '" + param1 + "'");
            
            while ( rs.next() ) {
                String lastName = rs.getString("Lname");
                System.out.println(lastName);
            }
            /**
             * The following line should be in a "finally" block.
             */
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
 
            /**
             * If "param1" is tainted, we have SQL Injection.
             */
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

	public boolean simpleSafeQuery(int searchID) throws SQLException{
		Connection conn = null;
        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
            /**
             * No issue here since parameter is an "int".
             */
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
	
	public void dumpAllCustomers() {
        try {
        	Connection conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
            ResultSet rs;
 
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

	public double unsafeRandomInTryCatchFinally() {
		// Simple test with rule firing in various parts of
		// try/catch/finally blocks.
		// Each block should complain about possible usage of
		// and unsafe random number.
		double returnValue;
		try {
			returnValue = unsafeRandom.nextDouble();
			if (returnValue < 0.0)
				return returnValue;
			throw new Exception("Value < 0.0");
		}
		catch (Exception e) {
			returnValue = unsafeRandom.nextDouble();
			return returnValue;
		}
		finally {
			returnValue = unsafeRandom.nextDouble();
			System.out.print(returnValue);
		}
	}

	public double unsafeRandomInTry() {
		// Simple test with rule firing in various parts of
		// try/catch/finally blocks
		double returnValue;
		try {
			returnValue = unsafeRandom.nextDouble();
			if (returnValue < 0.0)
				return returnValue;
			throw new Exception("Value < 0.0");
		}
		catch (Exception e) {
			returnValue = safeRandom.nextDouble();
			return returnValue;
		}
		finally {
			returnValue = safeRandom.nextDouble();
			System.out.print(returnValue);
		}
	}

	public double unsafeRandomInCatch() {
		// Simple test with rule firing in various parts of
		// try/catch/finally blocks
		double returnValue;
		try {
			returnValue = safeRandom.nextDouble();
			if (returnValue < 0.0)
				return returnValue;
			throw new Exception("Value < 0.0");
		}
		catch (Exception e) {
			returnValue = unsafeRandom.nextDouble();
			return returnValue;
		}
		finally {
			returnValue = safeRandom.nextDouble();
			System.out.print(returnValue);
		}
	}

	public double unsafeRandomInFinally() {
		// Simple test with rule firing in various parts of
		// try/catch/finally blocks
		double returnValue;
		try {
			returnValue = safeRandom.nextDouble();
			if (returnValue < 0.0)
				return returnValue;
			throw new Exception("Value < 0.0");
		}
		catch (Exception e) {
			returnValue = safeRandom.nextDouble();
			return returnValue;
		}
		finally {
			returnValue = unsafeRandom.nextDouble();
			System.out.print(returnValue);
		}
	}

	public void addTaintInCatch(HttpServletRequest request) {
		try {
			simpleSafeQuery(0);
		}
		catch (SQLException e) {
			simpleSqlQuery(request.getParameter("search_id"));
		}
	}

	public void addTaintInFinally(HttpServletRequest request) {
		try {
			dumpAllCustomers();
		}
		finally {
			simpleSqlQuery(request.getParameter("search_id"));
		}
	}

	public void addTaintInNestedCatch(HttpServletRequest request) {
		try {
			simpleSafeQuery(0);
		}
		catch (SQLException e) {
			try {
				simpleSafeQuery(-1);
			}
			catch (SQLException e2) {
				simpleSqlQuery(request.getParameter("search_id"));
			}
		}
	}
	
	private String returnLiteralString() {
		return "hello";
	}
	
	private String returnString() {
		return myString;
	}
	
	public void doSimpleStuff() {
		String s1 = "local init";
		String s2 = returnLiteralString();
		String s3 = returnString();
		String s4 = s1 + "-" + s2 + "-" + s3;
		int i = 0;
		Integer j = new Integer(2);
		int k = Integer.parseInt("1,000");
		int l;
		try {
			l = Integer.parseInt(s4);
		}
		catch (Exception e) {
			l = 0;
		}
		
		this.myInt = 50;
		this.myInt = i + j + k + l;
		
		AstExceptionTests.safeRandom = new SecureRandom();
	}

	public void doComplexStuff() {
		String s1;
		String myString;
		
		myString = "local variable";
		s1 = myString;
		s1 = this.myString;
		
		s1 = (myString.length() > 0) ? "" : this.myString;
	}
	
	private void taintMyString (HttpServletRequest request) {
		myString = request.getParameter("JSESSION");
	}
	
	private void threeParams(String p1, String p2, String p3) {
		simpleSqlQuery(p1);
		simpleSqlQuery(p2);
		simpleSqlQuery(p3);
	}
	
	public void doMoreComplexStuff(HttpServletRequest request) {
		/**
		 * These two calls should produce a SQL Injection issue.
		 */
		taintMyString(request);
		simpleSqlQuery(myString);
		
		/**
		 * Only the second call should yield a SQL Injection issue.
		 */
		threeParams("OK", "OK", "OK");
		threeParams("OK", myString, "OK");
		myString = "select * from users";
		threeParams("OK", myString, "OK");
	}

	private ResultSet executeQuery(String query) throws SQLException {
		Connection conn = null;

        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
 
            // Must follow taint to determine if this call is dangerous.
            return stmt.executeQuery(query);
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}

	public ResultSet getAllCustomers() throws SQLException {
		/**
		 * This is completely safe as the query is a literal string.
		 */
		return executeQuery(queryGetAllCustomers);
	}

	public boolean validCredentials(String username, String password)
	throws SQLException {
		Connection conn = null;

        try {
            conn = DriverManager.getConnection(connString,"","");
            Statement stmt = conn.createStatement();
 
            /**
             * Only calls with tainted data pose a problem.
             */
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
		/**
		 * No SQL Injection issue here.
		 */
		return validCredentials("admin", "password");
	}
	
	public boolean checkCredsTest2(String username, String password) {
		try {
			/**
			 * Must follow parameter taint to determine if call is safe.
			 */
			return validCredentials(username, password);
		}
		catch (Exception e) {
			return false;
		}
	}
	
	public boolean checkCredsTest3(String username, String password) {
		try {
			/**
			 * Must follow parameter taint to determine if call is safe.
			 */
			if(validCredentials(username, password))
				return true;
			
			/**
			 * This call is safe.
			 */
			return validCredentials("admin", "password");
		}
		catch (Exception e) {
			return false;
		}
	}
	
	public boolean checkUseOfFinalVariables(HttpServletRequest request) {
		try {
			/**
			 * All safe calls.
			 */
			executeQuery(finalPrivateQuery);
			executeQuery(finalPrivateQuery + " where seqnum=1");
			executeQuery(finalPrivateQuery + " where seqnum="
					+ Integer.parseInt(request.getParameter("ID")));
			executeQuery(finalPublicQuery);
			executeQuery(finalPublicQuery + " where seqnum=1");
			executeQuery(finalPublicQuery + " where seqnum="
					+ Integer.parseInt(request.getParameter("ID")));

			/**
			 * All unsafe calls.
			 */
			executeQuery(finalPrivateQuery + " where lastname='"
					+ request.getParameter("lname") + "'");
			executeQuery(finalPublicQuery + " where lastname='"
					+ request.getParameter("lname") + "'");
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

}
