package com.cigital.wbsa.test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

// There should not be any rules fired from this file!!
public class NoIssues {

	private String connString = "jdbc:msql://200.210.220.1:1114/Demo";

	public NoIssues() {
	}

	public void validCredentials(String username, String password)
	throws SQLException {
		Connection conn = null;

        try {
            conn = DriverManager.getConnection(connString, username, password);
            PreparedStatement ps = conn.prepareStatement("select * from table where col = '" + username + "'");
            ps.executeQuery();
        }
        finally {
        	if (conn != null)
        		conn.close();
        }
	}

	public void checkTaintPropogation1() {
		try {
			String username = "username";
			String password = "password";
			
			if (username.length() < 10) {
				validCredentials(username, password);
			} else {
				username = "";
				password = "";
				validCredentials(username, password);
			}
		} catch (Exception e) {
			// TODO
		}
	}

}
