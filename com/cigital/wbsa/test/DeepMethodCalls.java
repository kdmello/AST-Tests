package com.cigital.wbsa.test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;

import javax.servlet.http.HttpServletRequest;

public class DeepMethodCalls {
	
	private int myInt;

	public DeepMethodCalls() {
	}
	
	public void setSomeInt(int newValue) {
		myInt = newValue;
	}

	public void TestDeepWebTaintSimple(HttpServletRequest request) {
		// This line should fire rule (dangerous call).
		Simple1(request.getParameter("whatever"));
	}
	
	private void Simple1 (String p1) {
		Simple2(p1);
	}
	
	private void Simple2 (String p2) {
		Simple3(p2);
	}
 
	private void Simple3(String p3) {
		SimpleSink(p3);
	}

	private void SimpleSink(String pSink) {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");

			// This line should fire rule (SQL Injection).
            PreparedStatement ps = conn.prepareStatement("select * from table where col = ?");
            ps.setString(1, pSink);
            
            
            
            
           
            ps.execute();
        } catch (Exception e) {
        }
	}

	public void TestDeepWebTaintComplex(HttpServletRequest request) {
		if (myInt < 0) {
			// This line should fire rule (dangerous call).
			Complex1(request.getParameter("value1"));
		} else if (myInt > 0) {
			// This line should fire rule (dangerous call).
			Complex1(request.getParameter("value2"));
		} else {
			// This line should fire rule (dangerous call).
			Complex1(request.getParameter("value3"));
		}
	}
	 
	private void Complex1(String p1) {
		try {
			Complex2(p1);
		} catch (Exception e) {
			Complex2(null);
		}
	}
	
	private void Complex2(String p2) {
		Complex3("hello");
		Complex3(p2);
		Complex3(p2 + "goodbye");
		Complex3(p2 + Integer.toString(myInt));
	}
	
	private void Complex3(String p3) {
		ComplexSink(p3);
	}

	private void ComplexSink(String pSink) {
        try {
            String url = "jdbc:msql://200.210.220.1:1114/Demo";
            Connection conn = DriverManager.getConnection(url,"","");

    	    /** ** WRONG *** */
			// This line should fire rule (SQL Injection).
            String sql = "select * from table where col = '" + pSink + "'";
            PreparedStatement ps = conn.prepareStatement(sql);
            
            
    	    /** ** CORRECT *** */
//            PreparedStatement ps = conn.prepareStatement("select * from table where col = ?");
//            ps.setString(1, pSink);
    	    /** ** CORRECT *** */
            ps.execute();
        } catch (Exception e) {
        }
	}
}
