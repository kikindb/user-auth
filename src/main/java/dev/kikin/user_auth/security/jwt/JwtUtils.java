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
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

/**
 * Utility class for JSON Web Token (JWT) operations.
 * Handles generation, validation, and parsing of JWTs using asymmetric (RSA) keys.
 */
@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  // Private key for signing JWTs, loaded from application.properties (Base64 encoded PKCS8 format)
  @Value("${auth.app.jwtPrivateKey}")
  private String jwtPrivateKey;

  // Public key for verifying JWTs, loaded from application.properties (Base64 encoded X.509 format)
  @Value("${auth.app.jwtPublicKey}")
  private String jwtPublicKey;

  // Expiration time for JWTs in milliseconds, loaded from application.properties
  @Value("${auth.app.jwtExpirationMs}")
  private int jwtExpirationMs;

  /**
   * Generates a JWT token for an authenticated user.
   * The token includes the username as the subject and is signed with the private key.
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
        .signWith(getPrivateKey(), SignatureAlgorithm.RS256) // Sign the token with the private key using RS256 algorithm
        .compact(); // Build and compact the JWT into a string
  }

  /**
   * Retrieves the PrivateKey from the base64 encoded string.
   * Assumes PKCS8 format for the private key.
   *
   * @return The PrivateKey object for signing JWTs.
   */
  private PrivateKey getPrivateKey() {
    try {
      // Clean the key string: remove headers/footers, all whitespace (including newlines), and then trim
      String cleanKey = jwtPrivateKey
          .replaceAll("-----BEGIN PRIVATE KEY-----", "")
          .replaceAll("-----END PRIVATE KEY-----", "")
          .replaceAll("\\s", "") // Remove all whitespace characters
          .trim(); // Trim any remaining leading/trailing whitespace

      byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePrivate(spec);
    } catch (Exception e) {
      logger.error("Error loading private key: {}", e.getMessage());
      throw new RuntimeException("Error loading private key", e);
    }
  }

  /**
   * Retrieves the PublicKey from the base64 encoded string.
   * Assumes X.509 format for the public key.
   *
   * @return The PublicKey object for verifying JWTs.
   */
  private PublicKey getPublicKey() {
    try {
      // Clean the key string: remove headers/footers, all whitespace (including newlines), and then trim
      String cleanKey = jwtPublicKey
          .replaceAll("-----BEGIN PUBLIC KEY-----", "")
          .replaceAll("-----END PUBLIC KEY-----", "")
          .replaceAll("\\s", "") // Remove all whitespace characters
          .trim(); // Trim any remaining leading/trailing whitespace

      byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
      X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePublic(spec);
    } catch (Exception e) {
      logger.error("Error loading public key: {}", e.getMessage());
      throw new RuntimeException("Error loading public key", e);
    }
  }

  /**
   * Extracts the username from a JWT token.
   *
   * @param token The JWT token string.
   * @return The username extracted from the token's subject claim.
   */
  public String getUserNameFromJwtToken(String token) {
    // Parse the JWT and retrieve the subject (username) using the public key for verification
    return Jwts.parserBuilder().setSigningKey(getPublicKey()).build()
        .parseClaimsJws(token).getBody().getSubject();
  }

  /**
   * Validates a JWT token.
   * Checks for proper signature (using public key), expiration, and other common issues.
   *
   * @param authToken The JWT token string to validate.
   * @return True if the token is valid, false otherwise.
   */
  public boolean validateJwtToken(String authToken) {
    try {
      // Attempt to parse and validate the token using the public key
      Jwts.parserBuilder().setSigningKey(getPublicKey()).build().parse(authToken);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    } catch (SignatureException e) {
      logger.error("Invalid JWT signature: {}", e.getMessage());
    }
    return false;
  }
}
