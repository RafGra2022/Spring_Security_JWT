package com.security.controller;

public class ValidationException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3026106487616435508L;
	
	private	String detail;
	
	public ValidationException(String detail, String message) {
		super( message );
		this.detail = detail;
	}

	public String getDetail() {
		return detail;
	}
	
	
}
