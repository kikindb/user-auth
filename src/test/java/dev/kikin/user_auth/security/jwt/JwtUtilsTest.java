package dev.kikin.user_auth.security.jwt;

import dev.kikin.user_auth.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils; // For injecting @Value fields

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Unit tests for JwtUtils class.
 * Tests JWT token generation, validation, and username extraction using RSA keys.
 */
@ExtendWith(MockitoExtension.class) // Enables Mockito annotations for JUnit 5
class JwtUtilsTest {

  @InjectMocks // Injects mocks into JwtUtils instance
  private JwtUtils jwtUtils;

  @Mock // Mocks the Authentication object
  private Authentication authentication;

  // RSA KeyPair for testing
  private KeyPair keyPair;
  private RSAPrivateKey testPrivateKey;
  private RSAPublicKey testPublicKey;
  private String testKeyId;

  @BeforeEach
  void setUp() throws Exception {
    // Generate a new RSA key pair for each test
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048); // 2048-bit key size
    keyPair = keyPairGenerator.generateKeyPair();
    testPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
    testPublicKey = (RSAPublicKey) keyPair.getPublic();

    // Generate a fixed UUID for the Key ID for consistent testing
    testKeyId = UUID.randomUUID().toString();

    // Use ReflectionTestUtils to inject the private fields that are normally @Value
    // This simulates how Spring injects properties from application.properties
    ReflectionTestUtils.setField(jwtUtils, "jwtPrivateKey",
        "-----BEGIN PRIVATE KEY-----\n" +
            java.util.Base64.getEncoder().encodeToString(testPrivateKey.getEncoded()) +
            "\n-----END PRIVATE KEY-----");
    ReflectionTestUtils.setField(jwtUtils, "jwtPublicKey",
        "-----BEGIN PUBLIC KEY-----\n" +
            java.util.Base64.getEncoder().encodeToString(testPublicKey.getEncoded()) +
            "\n-----END PUBLIC KEY-----");
    ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", 300000); // 5 minutes
    ReflectionTestUtils.setField(jwtUtils, "keyId", testKeyId); // Inject the test Key ID
  }

  @Test
  @DisplayName("Should generate a valid JWT token")
  void generateJwtToken_shouldGenerateValidToken() {
    // Arrange
    UserDetailsImpl userDetails = new UserDetailsImpl(1L, "testuser", "test@example.com", "password",
        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
    when(authentication.getPrincipal()).thenReturn(userDetails);

    // Act
    String token = jwtUtils.generateJwtToken(authentication);

    // Assert
    assertNotNull(token);
    // Verify the token can be parsed and its claims are correct
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(testPublicKey) // Use the public key for verification
        .build()
        .parseClaimsJws(token)
        .getBody();

    assertEquals("testuser", claims.getSubject());
    assertTrue(claims.getIssuedAt().before(new Date()));
    assertTrue(claims.getExpiration().after(new Date()));
    assertEquals(testKeyId, Jwts.parserBuilder().setSigningKey(testPublicKey).build().parseClaimsJws(token).getHeader().get("kid"));
  }

  @Test
  @DisplayName("Should extract username from a valid JWT token")
  void getUserNameFromJwtToken_shouldExtractUsername() {
    // Arrange
    UserDetailsImpl userDetails = new UserDetailsImpl(1L, "testuser", "test@example.com", "password",
        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
    when(authentication.getPrincipal()).thenReturn(userDetails);
    String token = jwtUtils.generateJwtToken(authentication);

    // Act
    String username = jwtUtils.getUserNameFromJwtToken(token);

    // Assert
    assertEquals("testuser", username);
  }

  @Test
  @DisplayName("Should validate a valid JWT token")
  void validateJwtToken_shouldReturnTrueForValidToken() {
    // Arrange
    UserDetailsImpl userDetails = new UserDetailsImpl(1L, "testuser", "test@example.com", "password",
        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
    when(authentication.getPrincipal()).thenReturn(userDetails);
    String token = jwtUtils.generateJwtToken(authentication);

    // Act
    boolean isValid = jwtUtils.validateJwtToken(token);

    // Assert
    assertTrue(isValid);
  }

  @Test
  @DisplayName("Should return false for an expired JWT token")
  void validateJwtToken_shouldReturnFalseForExpiredToken() {
    // Arrange
    UserDetailsImpl userDetails = new UserDetailsImpl(1L, "expireduser", "expired@example.com", "password",
        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
    when(authentication.getPrincipal()).thenReturn(userDetails);

    // Temporarily set a very short expiration for this test
    ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", 1); // 1 millisecond
    String expiredToken = jwtUtils.generateJwtToken(authentication);

    // Wait for the token to expire
    try {
      Thread.sleep(100); // Wait a bit longer than 1ms
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }

    // Act
    boolean isValid = jwtUtils.validateJwtToken(expiredToken);

    // Assert
    assertFalse(isValid);
  }

  @Test
  @DisplayName("Should return false for a JWT token with invalid signature")
  void validateJwtToken_shouldReturnFalseForInvalidSignature() throws Exception {
    // Arrange
    // Generate a different key pair to sign a token
    KeyPairGenerator otherKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
    otherKeyPairGenerator.initialize(2048);
    KeyPair otherKeyPair = otherKeyPairGenerator.generateKeyPair();
    PrivateKey otherPrivateKey = otherKeyPair.getPrivate();

    // Create a token signed with the *other* private key
    String invalidToken = Jwts.builder()
        .setSubject("anotheruser")
        .setIssuedAt(new Date())
        .setExpiration(new Date((new Date()).getTime() + 300000))
        .signWith(otherPrivateKey, SignatureAlgorithm.RS256)
        .setHeaderParam("kid", "other-kid")
        .compact();

    // Act
    boolean isValid = jwtUtils.validateJwtToken(invalidToken);

    // Assert
    assertFalse(isValid);
  }

  @Test
  @DisplayName("Should return false for a malformed JWT token")
  void validateJwtToken_shouldReturnFalseForMalformedToken() {
    // Arrange
    String malformedToken = "invalid.jwt.token";

    // Act
    boolean isValid = jwtUtils.validateJwtToken(malformedToken);

    // Assert
    assertFalse(isValid);
  }

  @Test
  @DisplayName("Should return false for an unsupported JWT token")
  void validateJwtToken_shouldReturnFalseForUnsupportedToken() {
    // Arrange (e.g., a token signed with an unsupported algorithm)
    String unsupportedToken = Jwts.builder()
        .setSubject("unsupported")
        .setIssuedAt(new Date())
        .setExpiration(new Date((new Date()).getTime() + 300000))
        .signWith(Keys.secretKeyFor(SignatureAlgorithm.HS256)) // Use a different algorithm
        .compact();

    // Act
    boolean isValid = jwtUtils.validateJwtToken(unsupportedToken);

    // Assert
    assertFalse(isValid);
  }

  @Test
  @DisplayName("Should return false for an empty JWT claims string")
  void validateJwtToken_shouldReturnFalseForEmptyClaims() {
    // Arrange
    String emptyClaimsToken = ""; // Or a token with empty claims

    // Act
    boolean isValid = jwtUtils.validateJwtToken(emptyClaimsToken);

    // Assert
    assertFalse(isValid);
  }
}