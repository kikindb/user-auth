package dev.kikin.user_auth.security.jwt;

import dev.kikin.user_auth.security.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


public class AuthTokenFilter extends OncePerRequestFilter {
  @Autowired
  private JwtUtils jwtUtils;

  @Autowired
  private UserDetailsServiceImpl userDetailsService;

  private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

  /**
   * Performs the actual filtering logic for each request.
   *
   * @param request The HTTP servlet request.
   * @param response The HTTP servlet response.
   * @param filterChain The filter chain.
   * @throws ServletException If a servlet-specific error occurs.
   * @throws IOException If an I/O error occurs.
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    try {
      // 1. Get JWT from the Authorization header
      String jwt = parseJwt(request);

      // 2. If JWT exists and is valid, authenticate the user
      if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
        String username = jwtUtils.getUserNameFromJwtToken(jwt);

        // Load user details from the database
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Create an authentication object
        UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken(
                userDetails,
                null, // Credentials are not stored in the authentication object after successful auth
                userDetails.getAuthorities()); // Set user authorities (roles/permissions)

        // Set authentication details (e.g., remote address, session ID)
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        // Set the authentication object in the SecurityContextHolder
        // This indicates that the user is authenticated for the current request
        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    } catch (Exception e) {
      logger.error("Cannot set user authentication: {}", e.getMessage());
    }

    // Continue the filter chain
    filterChain.doFilter(request, response);
  }

  /**
   * Extracts the JWT token from the Authorization header of the request.
   * The token is expected to be in the format "Bearer <token>".
   *
   * @param request The HTTP servlet request.
   * @return The JWT token string, or null if not found or not in "Bearer" format.
   */
  private String parseJwt(HttpServletRequest request) {
    String headerAuth = request.getHeader("Authorization");

    if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
      return headerAuth.substring(7); // Extract the token after "Bearer "
    }
    return null;
  }
}
