package com.security.controller;

import java.io.UnsupportedEncodingException;
import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.util.JwtUtils;

import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.WeakKeyException;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/authorization")
@RequiredArgsConstructor
public class AuthorizationController {

	private final JwtUtils jwtUtils;
	private final AuthenticationManager authManager;
	private final UserRequestValidator validator;
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody UserRequest userRequest) throws WeakKeyException, InvalidKeyException, UnsupportedEncodingException{

		List<SimpleGrantedAuthority> roles = validator.validate(userRequest);
		
		Authentication authenticate = authManager
				.authenticate(new UsernamePasswordAuthenticationToken(userRequest.user(), userRequest.password()));
		
		if (authenticate.isAuthenticated()) {
			SecurityContextHolder.getContext().setAuthentication(authenticate);
		}
		
		String accessToken = jwtUtils
				.generateToken(new User(userRequest.user(), userRequest.password().toString(), roles), "access_token");

		return ResponseEntity.ok().body(new AuthenticatedResponse(authenticate.getName(), accessToken,
				jwtUtils.claimsFromToken(accessToken).getPayload().getExpiration()));
	}
}
