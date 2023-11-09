package com.luv2code.springboot.cruddemo.security;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class DemoSecurityConfig {

	@Bean
	public UserDetailsManager userDetailsManager(DataSource datasource) {
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(datasource);

		// Define query to retrieve a user by username
		jdbcUserDetailsManager.setUsersByUsernameQuery("select user_id,pw, active from members where user_id=?");

		// Define query to retrieve the authorities/roles
		jdbcUserDetailsManager.setAuthoritiesByUsernameQuery("select user_id, role from roles where user_id=?");

		return jdbcUserDetailsManager;
	}

	/*
	 * // add support for jdbc
	 * 
	 * @Bean public UserDetailsManager userDetailsManager(DataSource datasource) {
	 * return new JdbcUserDetailsManager(datasource); }
	 * 
	 */

	/*
	 * @Bean public InMemoryUserDetailsManager userDetailsManager() {
	 * 
	 * UserDetails akash = User.builder() .username("Akash")
	 * .password("{noop}akash123") .roles("EMPLOYEE") .build();
	 * 
	 * UserDetails ajit = User.builder() .username("Ajit")
	 * .password("{noop}ajit123") .roles("EMPLOYEE","MANAGER") .build();
	 * 
	 * UserDetails vaibhav = User.builder() .username("Vaibhav")
	 * .password("{noop}vaibhav123") .roles("EMPLOYEE","MANAGER","ADMIN") .build();
	 * 
	 * return new InMemoryUserDetailsManager(akash,ajit,vaibhav);
	 * 
	 * }
	 * 
	 */

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(configurer -> configurer

				.requestMatchers(HttpMethod.GET, "/api/employees").hasRole("EMPLOYEE")
				.requestMatchers(HttpMethod.GET, "/api/employees/**").hasRole("EMPLOYEE")
				.requestMatchers(HttpMethod.POST, "/api/employees").hasRole("MANAGER")
				.requestMatchers(HttpMethod.PUT, "/api/employees").hasRole("MANAGER")
				.requestMatchers(HttpMethod.DELETE, "/api/employees/**").hasRole("ADMIN")

		);

		// use HTTP basic authentication
		http.httpBasic(Customizer.withDefaults());

		// disable CSRF
		http.csrf(csrf -> csrf.disable());

		return http.build();
	}

}
