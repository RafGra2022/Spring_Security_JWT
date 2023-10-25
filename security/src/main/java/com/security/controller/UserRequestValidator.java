package com.security.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class UserRequestValidator {

	private List<String> roles;

	@Value("${roles}")
	public void setRole(List<String> roles) {
		this.roles = roles;
	}

	public List<SimpleGrantedAuthority> validate(UserRequest userRequest) {

		List<SimpleGrantedAuthority> grantedRoles = new ArrayList<SimpleGrantedAuthority>();
		for (String role : roles) {
			if (role.equalsIgnoreCase(userRequest.role())) {
				grantedRoles.add(new SimpleGrantedAuthority(userRequest.role().toUpperCase()));
			}
		}
		if(userRequest.user() == null ) {
			throw new ValidationException("'user' ", "is mandatory");
		}
		else if(userRequest.password() == null ) {
			throw new ValidationException("'password' ", "is mandatory");
		}
		else if (grantedRoles.isEmpty()) {
			throw new ValidationException("'role' ", "acceptable values : 'ADMIN','USER'");
		}
		return grantedRoles;
	}

}
