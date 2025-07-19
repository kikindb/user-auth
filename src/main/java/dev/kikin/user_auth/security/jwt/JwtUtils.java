package dev.kikin.user_auth.security.jwt;

import dev.kikin.user_auth.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  // Secret key for signing JWTs, loaded from application.properties
  @Value("${auth.app.jwtSecret}")
  private String jwtSecret;

  // Expiration time for JWTs in milliseconds, loaded from application.properties
  @Value("${auth.app.jwtExpirationMs}")
  private int jwtExpirationMs;

  /**
   * Generates a JWT token for an authenticated user.
   * The token includes the username as the subject and is signed with the secret key.
   *
   * @param authentication The authentication object containing user details.
   * @return The generated JWT string.
   */
  public String generateJwtToken(Authentication authentication) {
    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

    return Jwts.builder()
        .setSubject((userPrincipal.getUsername())) // Set the subject of the token to the username
        .setIssuedAt(new Date()) // Set the token issuance date
        .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)) // Set the token expiration date
        .signWith(key(), SignatureAlgorithm.HS256) // Sign the token with the secret key using HS256 algorithm
        .compact(); // Build and compact the JWT into a string
  }

  /**
   * Retrieves the signing key from the base64 encoded secret.
   *
   * @return The Key object for signing/verifying JWTs.
   */
  private Key key() {
    // Decode the base64 secret string into bytes and create a SecretKey
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  /**
   * Extracts the username from a JWT token.
   *
   * @param token The JWT token string.
   * @return The username extracted from the token's subject claim.
   */
  public String getUserNameFromJwtToken(String token) {
    // Parse the JWT and retrieve the subject (username)
    return Jwts.parserBuilder().setSigningKey(key()).build()
        .parseClaimsJws(token).getBody().getSubject();
  }

  /**
   * Validates a JWT token.
   * Checks for proper signature, expiration, and other common issues.
   *
   * @param authToken The JWT token string to validate.
   * @return True if the token is valid, false otherwise.
   */
  public boolean validateJwtToken(String authToken) {
    try {
      // Attempt to parse and validate the token using the signing key
      Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }
    return false;
  }
}
