package com.security.controller;


import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class SecurityExceptionHandler {

	
	@ExceptionHandler(ValidationException.class)
	public ResponseEntity<ErrorDetail> validationException(ValidationException e) {
		return ResponseEntity.badRequest().body(new ErrorDetail("VALIDATION_ERROR",e.getDetail(),e.getMessage()));
	}
	
	@ExceptionHandler(AuthenticationException.class)
	public ResponseEntity<ErrorDetail> badCredential(){
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorDetail("AuthenticationException",null,"Bad credentials"));
	}
}
