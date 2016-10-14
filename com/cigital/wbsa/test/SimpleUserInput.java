/**
 * Test cases for Secure Assist plug-in.
 * These focus on problems starting with user input.
 */
package com.cigital.wbsa.test;

import java.io.IOException;
import javax.servlet.http.*;

public class SimpleUserInput {

	public boolean checkLogin(HttpServletRequest request) {
		try {
			// This line should fire rule (dangerous call).
			String username = request.getParameter("username");
			// This line should fire rule (dangerous call).
			String password = request.getParameter("password");
			
			ComplexDbAccess temp = new ComplexDbAccess();
			// This line should fire rule (SQL Injection).
			return temp.validCredentials(username, password);
		}
		catch (Exception e) {
			return false;
		}
	}
	
	public void trustViolation(
			HttpServletRequest request, HttpServletResponse response)
	throws IOException {
		// This line should fire rule (dangerous call).
		String newPage = request.getParameter("newPage");

		// This line should fire rule (URL manipulation).
		response.sendRedirect(newPage);
	}
	
	private String getNewPage(HttpServletRequest request) {
		// This line should fire rule (dangerous call).
		return request.getParameter("newPage");
	}
	
	private String getNewPageSafe(HttpServletRequest request) {
		// This line should fire rule (dangerous call).
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
		// This line should fire rule (URL manipulation).
		response.sendRedirect(getNewPage(request));
	}
	
	public void noTrustViolation1(
			HttpServletRequest request, HttpServletResponse response)
	throws IOException {
		// This line should not fire rule.
		response.sendRedirect(getNewPageSafe(request));
	}
	
	public void noTrustViolation2(
			HttpServletRequest request, HttpServletResponse response)
	throws IOException {
		// This line should fire rule (dangerous call).
		String newPage = request.getParameter("newPage");
		if (newPage.equals("redirect1"))
			newPage = "redirect1";
		else if (newPage.equals("redirect2"))
			newPage = "redirect2";
		else
			newPage = "";

		// This line should not fire rule.
		response.sendRedirect(newPage);
	}

}
