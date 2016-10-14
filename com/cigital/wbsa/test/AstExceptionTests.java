/**
 * Test cases for Secure Assist plug-in.
 * These focus on exception handling.
 */
package com.cigital.wbsa.test;

import java.security.*;
import java.util.*;
import java.sql.*;

import javax.servlet.http.HttpServletRequest;

public class AstExceptionTests {
	// This line should fire rule.
	private Random unsafeRandom = new Random();
	static public SecureRandom safeRandom = new SecureRandom();
	private SimpleDbAccess simpleDbAccess = new SimpleDbAccess();
	
	public void throwExceptionInFinallyBlock() throws Exception {
		try {
			throw new Exception("Thrown from try");
		}
		finally {
			Exception eTemp = new Exception("test");
			try {
				throw new Exception("Thrown from finally");
			}
			catch (Exception e) {
				
			}
		}
	}

	public double unsafeRandomInTryCatchFinally() {
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
			simpleDbAccess.simpleSafeQuery(0);
		}
		catch (SQLException e) {
			// This line should fire rule (SQL Injection).
			simpleDbAccess.simpleSqlQuery(request.getParameter("search_id"));
		}
	}

	public void addTaintInFinally(HttpServletRequest request) {
		try {
			simpleDbAccess.dumpAllCustomers();
		}
		finally {
			// This line should fire rule (SQL Injection).
			simpleDbAccess.simpleSqlQuery(request.getParameter("search_id"));
		}
	}

	public void addTaintInNestedCatch(HttpServletRequest request) {
		try {
			simpleDbAccess.simpleSafeQuery(0);
		}
		catch (SQLException e) {
			try {
				simpleDbAccess.simpleSafeQuery(-1);
			}
			catch (SQLException e2) {
				// This line should fire rule (SQL Injection).
				simpleDbAccess.simpleSqlQuery(request.getParameter("search_id"));
			}
		}
	}

}
