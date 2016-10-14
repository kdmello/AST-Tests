/**
 * Test cases for Secure Assist plug-in.
 * These focus on some of the simple patterns that should be easy to detect.
 */
package com.cigital.wbsa.test;

import java.sql.*;

import javax.servlet.http.*;

public class SimpleDbPrepStmt {
	private static final String strSafeQuery1 = "select * from table";
	
	private String clean(String s){
		//magic
		
		return s;
	}
	
	public boolean unsafeQueryUsingUnsafeString(HttpServletRequest request) {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            ResultSet rs;
			// This line should fire rule (dangerous call).
            String p1 = request.getParameter("lname");
 
			// This line should fire rule (SQL Injection).
            PreparedStatement ps = conn.prepareStatement("select * from table where col =" + p1);
            //ps.setString(1, p1);
            rs = ps.executeQuery();
            return rs.first();
        } catch (Exception e) {
        	/**
        	 * Catching a broad exception can be dangerous.
        	 */
            System.err.println(e.getMessage());
            return false;
        }
	}

	public boolean safeQueryUsingParameter(String p1) {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            ResultSet rs;
 
            PreparedStatement ps = conn.prepareStatement(strSafeQuery1 + " where col = ?");
        	ps.setString(0, p1);
			// This line should not fire rule.
            rs = ps.executeQuery();
            return rs.first();
        } catch (Exception e) {
        	/**
        	 * Catching a broad exception can be dangerous.
        	 */
            System.err.println(e.getMessage());
            return false;
        }
	}

	public boolean gotStates() {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            ResultSet rs;
 
            PreparedStatement ps = conn.prepareStatement("select * from StateAbbreviations");
			// This line should not fire rule (literal string used).
            rs = ps.executeQuery();
            return rs.first();
        } catch (Exception e) {
        	/**
        	 * Catching a broad exception can be dangerous.
        	 */
            System.err.println(e.getMessage());
            return false;
        }
	}
	
	public boolean execQueryFromFinalString() {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            ResultSet rs;
 
			// This line should not fire rule (query cannot be altered).
            PreparedStatement ps = conn.prepareStatement(strSafeQuery1);
            rs = ps.executeQuery();
            if (rs.first()) {
    			// This line should not fire rule (query cannot be altered).
            	ps = conn.prepareStatement(strSafeQuery1 + " where col = 3");
                rs = ps.executeQuery();
            }
            return rs.first();
        } catch (Exception e) {
        	/**
        	 * Catching a broad exception can be dangerous.
        	 */
            System.err.println(e.getMessage());
            return false;
        }
	}
	
	public boolean unsafeQueryUsingParameter(String p1) {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");
            ResultSet rs;
 
            // This line should only fire rule when "p1" is tainted.
            PreparedStatement ps = conn.prepareStatement(strSafeQuery1 
            		+ " where col = '" + p1 + "'");
            rs = ps.executeQuery();
            return rs.first();
        } catch (Exception e) {
        	/**
        	 * Catching a broad exception can be dangerous.
        	 */
            System.err.println(e.getMessage());
            return false;
        }
	}

}
