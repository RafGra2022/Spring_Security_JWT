package com.security.util;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;

@Component
public class JwtUtils {
	
	private String secret;
	private int jwtExpirationInMs;

	@Value("${jwt.secret}")
	public void setSecret(String secret) {
		this.secret = secret;
	}

	@Value("${jwt.expirationDateInMs}")
	public void setJwtExpirationInMs(int jwtExpirationInMs) {
		this.jwtExpirationInMs = jwtExpirationInMs;
	}

	public String generateToken(UserDetails userDetails, String type) throws WeakKeyException, InvalidKeyException, UnsupportedEncodingException {
		Map<String, String> claims = new HashMap<>();

		Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();
		if(type.equalsIgnoreCase("access_token")) {
			claims.put(type, "access_token");
		}
		
		if(type.equalsIgnoreCase("refresh_token")) {
			claims.put(type, "refresh_token");
		}
		
		if (roles.contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
			claims.put("isAdmin", "true");
		}
		if (roles.contains(new SimpleGrantedAuthority("ROLE_USER"))) {
			claims.put("isUser", "false");
		}

		return doGenerateToken(claims, userDetails.getUsername());
	}

	public String doGenerateToken(Map<String, String> claims, String subject) throws WeakKeyException, InvalidKeyException, UnsupportedEncodingException {
		return Jwts.builder().claims(claims).subject(subject).issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + jwtExpirationInMs))
				.signWith(Keys.hmacShaKeyFor(Base64.getEncoder().encode(secret.getBytes()))).compact();
		
	}
	
	public boolean validate(String authToken) {
		try {
			claimsFromToken(authToken);
			return true;
		} catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
			throw new BadCredentialsException("INVALID_CREDENTIALS", ex);
		} catch (ExpiredJwtException ex) {
			throw ex;
		}
	}

	public Jws<Claims> claimsFromToken(String token) {
		return Jwts.parser().verifyWith(Keys.hmacShaKeyFor(Base64.getEncoder().encode(secret.getBytes()))).build()
				.parseSignedClaims(token);
	}
	
	public String getUsername(String token) {
		Jws<Claims> claims = claimsFromToken(token);
		return claims.getPayload().getSubject();
	}
}
