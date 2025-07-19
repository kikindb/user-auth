package dev.kikin.user_auth.security;

import dev.kikin.user_auth.security.jwt.AuthEntryPointJwt;
import dev.kikin.user_auth.security.jwt.AuthTokenFilter;
import dev.kikin.user_auth.security.services.UserDetailsServiceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Main Spring Security configuration class for the authentication microservice.
 * This class defines security rules, password encoder, authentication manager,
 * and integrates JWT authentication.
 */
@Configuration // Marks this class as a Spring configuration class
@EnableMethodSecurity // Enables method-level security annotations like @PreAuthorize
public class WebSecurityConfig {

  @Autowired
  UserDetailsServiceImpl userDetailsService; // Service to load user details

  @Autowired
  private AuthEntryPointJwt unauthorizedHandler; // Handles unauthorized access attempts

  /**
   * Creates and returns an instance of AuthTokenFilter.
   * This filter is responsible for parsing and validating JWT tokens in incoming requests.
   *
   * @return A new AuthTokenFilter instance.
   */
  @Bean
  public AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter();
  }

  /**
   * Configures the DaoAuthenticationProvider, which uses our custom UserDetailsService
   * and a password encoder to authenticate users.
   *
   * @return A configured DaoAuthenticationProvider.
   */
  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

    authProvider.setUserDetailsService(userDetailsService); // Set our custom UserDetailsService
    authProvider.setPasswordEncoder(passwordEncoder()); // Set the password encoder

    return authProvider;
  }

  /**
   * Provides the AuthenticationManager bean.
   * The AuthenticationManager is used to authenticate user credentials.
   *
   * @param authConfig The AuthenticationConfiguration.
   * @return The AuthenticationManager instance.
   * @throws Exception If an error occurs during configuration.
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
    return authConfig.getAuthenticationManager();
  }

  /**
   * Provides a BCryptPasswordEncoder bean for hashing passwords.
   * BCrypt is a strong hashing algorithm recommended for password storage.
   *
   * @return A BCryptPasswordEncoder instance.
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /**
   * Configures the security filter chain.
   * This method defines which requests are permitted, how sessions are managed,
   * and integrates our JWT authentication filter.
   *
   * @param http The HttpSecurity object to configure.
   * @return The configured SecurityFilterChain.
   * @throws Exception If an error occurs during configuration.
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable()) // Disable CSRF for stateless APIs
        .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler)) // Set unauthorized handler
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Use stateless sessions (JWT)
        .authorizeHttpRequests(auth ->
            auth.requestMatchers("/api/auth/**").permitAll() // Permit all requests to /api/auth (for login/registration/refresh)
                .requestMatchers("/api/test/**").permitAll() // Permit all requests to /api/test (for testing roles/permissions)
                .requestMatchers("/health").permitAll()
                .anyRequest().authenticated() // All other requests require authentication
        );

    http.authenticationProvider(authenticationProvider()); // Set our custom authentication provider

    // Add our JWT authentication filter before the UsernamePasswordAuthenticationFilter
    http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }
}