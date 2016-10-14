/**
 * Test cases for Secure Assist plug-in.
 * These focus on making sure the engine generates a proper AST tree for
 * a variety of assignment examples.
 */
package com.cigital.wbsa.test;

import java.security.*;

import javax.servlet.http.HttpServletRequest;

public class Assignments {

	private String myString;
	private SimpleDbAccess myDbAccess;
	private int myInt = -9999;
	static private boolean myStatus = false;
	
	public Assignments() {
		myString = "initial value";
		myDbAccess = new SimpleDbAccess();
		myStatus = true;
	}
	
	private String returnLiteralString() {
		return "hello";
	}
	
	private String returnString() {
		return myString;
	}
	
	public boolean returnStatus() {
		return myStatus;
	}
	
	public int returnInt() {
		return myInt;
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

	public String doComplexStuff() {
		String s1;
		String myString;
		
		myString = "local variable";
		s1 = myString;
		s1 = this.myString;
		
		s1 = (myString.length() > 0) ? "" : this.myString;
		return s1;
	}
	
	private void taintMyString (HttpServletRequest request) {
		// This line should fire rule (dangerous call).
		myString = request.getParameter("JSESSION");
	}
	
	private void threeParams(String p1, String p2, String p3) {
		myDbAccess.simpleSqlQuery(p1);
		myDbAccess.simpleSqlQuery(p2);
		myDbAccess.simpleSqlQuery(p3);
	}
	
	public void doMoreComplexStuff(HttpServletRequest request) {
		taintMyString(request);
		// This line should fire rule (SQL Injection).
		myDbAccess.simpleSqlQuery(myString);
		
		threeParams("OK", "OK", "OK");
		// This line should fire rule (SQL Injection).
		threeParams("OK", myString, "OK");
		myString = "select * from users";
		threeParams("OK", myString, "OK");
	}
	
}
