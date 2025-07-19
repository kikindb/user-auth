package dev.kikin.user_auth.security.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Handles unauthorized access attempts in a Spring Security context.
 * This class is invoked when an unauthenticated user tries to access a protected resource.
 * It sends a 401 Unauthorized response.
 */
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

  private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

  /**
   * Commences an authentication scheme.
   *
   * @param request The HTTP servlet request.
   * @param response The HTTP servlet response.
   * @param authException The authentication exception that caused the commencement.
   * @throws IOException If an I/O error occurs.
   * @throws ServletException If a servlet-specific error occurs.
   */
  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
      throws IOException, ServletException {
    logger.error("Unauthorized error: {}", authException.getMessage());
    // Send a 401 Unauthorized response, indicating that authentication is required.
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
  }
}