package com.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class CustomUserServiceConfig {

	@Bean
	UserDetailsService userDetailsService() {

		UserDetails rafal = User.builder().username("Rafal")
				.password("$2a$12$/4rWpdHtR1180h9IAfHPceVvxMjo4QzF5rvR10uYCdaXK/.9gwN2G").roles("ADMIN").build();

		return new InMemoryUserDetailsManager(rafal);
	}
}
