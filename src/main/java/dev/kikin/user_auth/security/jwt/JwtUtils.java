package dev.kikin.user_auth.security.jwt;

import dev.kikin.user_auth.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID; // Importar UUID

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

  // ID de la clave pública, usado en el JWKS. Un UUID fijo para el ejemplo.
  // En producción, podrías generar esto dinámicamente o usar un hash de la clave.
  private final String keyId = UUID.randomUUID().toString(); // Generar un Key ID único al inicio

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
        .setHeaderParam("kid", keyId) // Añade el Key ID al encabezado del JWT
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
  public RSAPublicKey getPublicKey() { // Cambiado a RSAPublicKey
    try {
      // Limpia la cadena de la clave: elimina encabezados/pies de página, todos los espacios en blanco (incluidas las nuevas líneas) y luego recorta
      String cleanKey = jwtPublicKey
          .replaceAll("-----BEGIN PUBLIC KEY-----", "")
          .replaceAll("-----END PUBLIC KEY-----", "")
          .replaceAll("\\s", "") // Elimina todos los caracteres de espacio en blanco
          .trim(); // Recorta cualquier espacio en blanco inicial/final restante

      byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
      X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return (RSAPublicKey) kf.generatePublic(spec); // Casteado a RSAPublicKey
    } catch (Exception e) {
      logger.error("Error al cargar la clave pública: {}", e.getMessage());
      throw new RuntimeException("Error al cargar la clave pública", e);
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

  /**
   * Obtiene el Key ID (kid) utilizado para firmar los JWTs.
   * @return El Key ID.
   */
  public String getKeyId() {
    return keyId;
  }
}
