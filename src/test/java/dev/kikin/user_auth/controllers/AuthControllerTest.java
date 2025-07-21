package dev.kikin.user_auth.controllers;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import dev.kikin.user_auth.entity.RefreshToken;
import dev.kikin.user_auth.entity.Role;
import dev.kikin.user_auth.entity.User;
import dev.kikin.user_auth.exceptions.TokenRefreshException;
import dev.kikin.user_auth.payload.request.LoginRequest;
import dev.kikin.user_auth.payload.request.SignupRequest;
import dev.kikin.user_auth.payload.request.TokenRefreshRequest;
import dev.kikin.user_auth.payload.request.JwtResponse;
import dev.kikin.user_auth.payload.response.MessageResponse;
import dev.kikin.user_auth.payload.response.TokenRefreshResponse;
import dev.kikin.user_auth.repository.RoleRepository;
import dev.kikin.user_auth.repository.UserRepository;
import dev.kikin.user_auth.security.jwt.JwtUtils;
import dev.kikin.user_auth.security.services.UserDetailsImpl;
import dev.kikin.user_auth.services.RefreshTokenService;
import org.junit.jupiter.api.AfterEach; // Added import
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuthController class.
 * Tests user signup, signin, and refresh token functionalities.
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

  @Mock
  private AuthenticationManager authenticationManager;

  @Mock
  private UserRepository userRepository;

  @Mock
  private RoleRepository roleRepository;

  @Mock
  private PasswordEncoder encoder;

  @Mock
  private JwtUtils jwtUtils;

  @Mock
  private RefreshTokenService refreshTokenService;

  @InjectMocks
  private AuthController authController;

  private User testUser;
  private UserDetailsImpl userDetails;
  private RefreshToken testRefreshToken;

  @BeforeEach
  void setUp() {
    testUser = new User("testuser", "encodedpassword", "test@example.com");
    testUser.setId(1L);
    Set<Role> roles = new HashSet<>();
    roles.add(new Role("ROLE_USER"));
    testUser.setRoles(roles);

    userDetails = UserDetailsImpl.build(testUser);

    testRefreshToken = new RefreshToken();
    testRefreshToken.setToken("mockRefreshToken");
    testRefreshToken.setUser(testUser);
    testRefreshToken.setExpiryDate(java.time.Instant.now().plusSeconds(3600)); // 1 hour from now

    // Initialize SecurityContextHolder for each test
    // This ensures a clean state and allows AuthController to set authentication
    SecurityContextHolder.clearContext(); // Clear any previous context
  }

  @AfterEach // Added to clear SecurityContextHolder after each test
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  @DisplayName("Should successfully authenticate user and return JWT and Refresh Token")
  void authenticateUser_success() {
    // Arrange
    LoginRequest loginRequest = new LoginRequest("testuser", "password");
    Authentication authentication = mock(Authentication.class);
    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
    when(authentication.getPrincipal()).thenReturn(userDetails);
    when(jwtUtils.generateJwtToken(authentication)).thenReturn("mockAccessToken");
    when(refreshTokenService.createRefreshToken(anyLong())).thenReturn(testRefreshToken);

    // Act
    ResponseEntity<?> responseEntity = authController.authenticateUser(loginRequest);

    // Assert
    assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    assertTrue(responseEntity.getBody() instanceof JwtResponse);
    JwtResponse jwtResponse = (JwtResponse) responseEntity.getBody();
    assertEquals("mockAccessToken", jwtResponse.getAccessToken());
    assertEquals("mockRefreshToken", jwtResponse.getRefreshToken());
    assertEquals(testUser.getUsername(), jwtResponse.getUsername());
    assertEquals(testUser.getEmail(), jwtResponse.getEmail());
    assertEquals(testUser.getId(), jwtResponse.getId());
    assertEquals(Collections.singletonList("ROLE_USER"), jwtResponse.getRoles());

    verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
    verify(jwtUtils, times(1)).generateJwtToken(authentication);
    verify(refreshTokenService, times(1)).createRefreshToken(testUser.getId());
    // Verify that the SecurityContextHolder's authentication was set
    assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    assertEquals(userDetails, SecurityContextHolder.getContext().getAuthentication().getPrincipal());
  }

  @Test
  @DisplayName("Should return Bad Request for invalid login credentials")
  void authenticateUser_invalidCredentials() {
    // Arrange
    LoginRequest loginRequest = new LoginRequest("wronguser", "wrongpassword");
    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenThrow(new BadCredentialsException("Bad credentials"));

    // Act & Assert
    assertThrows(BadCredentialsException.class, () -> authController.authenticateUser(loginRequest));

    verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
    verifyNoInteractions(jwtUtils, refreshTokenService); // No token generation or refresh token creation
    assertNull(SecurityContextHolder.getContext().getAuthentication()); // Should not set authentication on failure
  }

  @Test
  @DisplayName("Should successfully register a new user with default role")
  void registerUser_successWithDefaultRole() {
    // Arrange
    SignupRequest signupRequest = new SignupRequest("newuser", "new@example.com", "newpassword", null);
    when(userRepository.existsByUsername("newuser")).thenReturn(false);
    when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
    when(encoder.encode("newpassword")).thenReturn("encodednewpassword");
    when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(new Role("ROLE_USER")));
    when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0)); // Return the saved user

    // Act
    ResponseEntity<?> responseEntity = authController.registerUser(signupRequest);

    // Assert
    assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    assertTrue(responseEntity.getBody() instanceof MessageResponse);
    MessageResponse messageResponse = (MessageResponse) responseEntity.getBody();
    assertEquals("User registered successfully!", messageResponse.getMessage());

    verify(userRepository, times(1)).existsByUsername("newuser");
    verify(userRepository, times(1)).existsByEmail("new@example.com");
    verify(encoder, times(1)).encode("newpassword");
    verify(roleRepository, times(1)).findByName("ROLE_USER");
    verify(userRepository, times(1)).save(any(User.class));
  }

  @Test
  @DisplayName("Should return Bad Request if username already exists during registration")
  void registerUser_usernameExists() {
    // Arrange
    SignupRequest signupRequest = new SignupRequest("existinguser", "new@example.com", "password", null);
    when(userRepository.existsByUsername("existinguser")).thenReturn(true);

    // Act
    ResponseEntity<?> responseEntity = authController.registerUser(signupRequest);

    // Assert
    assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
    assertTrue(responseEntity.getBody() instanceof MessageResponse);
    MessageResponse messageResponse = (MessageResponse) responseEntity.getBody();
    assertEquals("Error: Username is already taken!", messageResponse.getMessage());

    verify(userRepository, times(1)).existsByUsername("existinguser");
    verify(userRepository, never()).existsByEmail(anyString()); // Should not proceed to check email
    verify(encoder, never()).encode(anyString());
    verify(roleRepository, never()).findByName(anyString());
    verify(userRepository, never()).save(any(User.class));
  }

  @Test
  @DisplayName("Should return Bad Request if email already exists during registration")
  void registerUser_emailExists() {
    // Arrange
    SignupRequest signupRequest = new SignupRequest("newuser", "existing@example.com", "password", null);
    when(userRepository.existsByUsername("newuser")).thenReturn(false);
    when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

    // Act
    ResponseEntity<?> responseEntity = authController.registerUser(signupRequest);

    // Assert
    assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
    assertTrue(responseEntity.getBody() instanceof MessageResponse);
    MessageResponse messageResponse = (MessageResponse) responseEntity.getBody();
    assertEquals("Error: Email is already in use!", messageResponse.getMessage());

    verify(userRepository, times(1)).existsByUsername("newuser");
    verify(userRepository, times(1)).existsByEmail("existing@example.com");
    verify(encoder, never()).encode(anyString());
    verify(roleRepository, never()).findByName(anyString());
    verify(userRepository, never()).save(any(User.class));
  }

  @Test
  @DisplayName("Should successfully refresh token and return new Access Token")
  void refreshToken_success() {
    // Arrange
    TokenRefreshRequest request = new TokenRefreshRequest("validRefreshToken");

    // 1. Mock findByToken to return an Optional containing the testRefreshToken
    when(refreshTokenService.findByToken("validRefreshToken")).thenReturn(Optional.of(testRefreshToken));

    // 2. Mock verifyExpiration to return the same testRefreshToken (simulating verification success)
    when(refreshTokenService.verifyExpiration(testRefreshToken)).thenReturn(testRefreshToken);

    // Note: The subsequent .map(RefreshToken::getUser) will be called on the actual testRefreshToken object,
    // which has testUser set on it in the setUp method, so no explicit mock is needed for getUser().

    // 3. Mock the generation of a new access token by JwtUtils
    String newMockAccessToken = "newMockAccessToken";
    when(jwtUtils.generateJwtToken(any(UsernamePasswordAuthenticationToken.class))).thenReturn(newMockAccessToken);

    // Act
    ResponseEntity<?> responseEntity = authController.refreshtoken(request);

    // Assert
    assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    assertTrue(responseEntity.getBody() instanceof TokenRefreshResponse);
    TokenRefreshResponse refreshResponse = (TokenRefreshResponse) responseEntity.getBody();
    assertEquals(newMockAccessToken, refreshResponse.getAccessToken());
    assertEquals("validRefreshToken", refreshResponse.getRefreshToken());
    assertEquals("Bearer", refreshResponse.getTokenType());

    // Verify interactions
    verify(refreshTokenService, times(1)).findByToken("validRefreshToken");
    verify(refreshTokenService, times(1)).verifyExpiration(testRefreshToken);
    verify(jwtUtils, times(1)).generateJwtToken(any(UsernamePasswordAuthenticationToken.class));
  }

  @Test
  @DisplayName("Should throw TokenRefreshException if refresh token is not in database")
  void refreshToken_tokenNotFound() {
    // Arrange
    TokenRefreshRequest request = new TokenRefreshRequest("nonExistentToken");
    when(refreshTokenService.findByToken("nonExistentToken")).thenReturn(Optional.empty());

    // Act & Assert
    TokenRefreshException exception = assertThrows(TokenRefreshException.class,
        () -> authController.refreshtoken(request));

    assertEquals("Failed for [nonExistentToken]: Refresh token is not in database!", exception.getMessage());
    verify(refreshTokenService, times(1)).findByToken("nonExistentToken");
    verify(refreshTokenService, never()).verifyExpiration(any(RefreshToken.class));
    verifyNoInteractions(jwtUtils);
  }

  @Test
  @DisplayName("Should throw TokenRefreshException if refresh token is expired")
  void refreshToken_tokenExpired() {
    // Arrange
    TokenRefreshRequest request = new TokenRefreshRequest("expiredRefreshToken");
    RefreshToken expiredRefreshToken = new RefreshToken();
    expiredRefreshToken.setToken("expiredRefreshToken");
    expiredRefreshToken.setExpiryDate(java.time.Instant.now().minusSeconds(100)); // Expired
    expiredRefreshToken.setUser(testUser); // Ensure user is set for the expired token

    when(refreshTokenService.findByToken("expiredRefreshToken")).thenReturn(Optional.of(expiredRefreshToken));
    when(refreshTokenService.verifyExpiration(expiredRefreshToken))
        .thenThrow(new TokenRefreshException("expiredRefreshToken", "Refresh token was expired. Please make a new signin request"));

    // Act & Assert
    TokenRefreshException exception = assertThrows(TokenRefreshException.class,
        () -> authController.refreshtoken(request));

    assertEquals("Failed for [expiredRefreshToken]: Refresh token was expired. Please make a new signin request", exception.getMessage());
    verify(refreshTokenService, times(1)).findByToken("expiredRefreshToken");
    verify(refreshTokenService, times(1)).verifyExpiration(expiredRefreshToken);
    verifyNoInteractions(jwtUtils);
  }

  @Test
  @DisplayName("Should return JWKS with correct public key and kid")
  void jwks_shouldReturnCorrectJwks() throws Exception {
    // Arrange
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair pair = keyGen.generateKeyPair();
    RSAPublicKey mockPublicKey = (RSAPublicKey) pair.getPublic();
    String mockKeyId = "mock-kid-123";

    when(jwtUtils.getPublicKey()).thenReturn(mockPublicKey);
    when(jwtUtils.getKeyId()).thenReturn(mockKeyId);

    // Act
    // The actual method returns Map<String, Object>
    Map<String, Object> jwksResponse = authController.jwks();

    // Assert
    assertNotNull(jwksResponse);
    assertTrue(jwksResponse.containsKey("keys"));
    // The "keys" value is a List of Maps (JSON objects), not List of JWK
    List<Map<String, Object>> keysList = (List<Map<String, Object>>) jwksResponse.get("keys");
    assertFalse(keysList.isEmpty());

    // Parse the first key map back into a JWK object for proper assertion
    JWK jwk = JWK.parse(keysList.get(0));
    assertTrue(jwk instanceof RSAKey);
    RSAKey rsaJwk = (RSAKey) jwk;

    assertEquals("RSA", rsaJwk.getKeyType().toString());
    assertEquals("sig", rsaJwk.getKeyUse().getValue());
    assertEquals("RS256", rsaJwk.getAlgorithm().getName());
    assertEquals(mockKeyId, rsaJwk.getKeyID());
    assertEquals(mockPublicKey.getPublicExponent(), rsaJwk.getPublicExponent().decodeToBigInteger());
    assertEquals(mockPublicKey.getModulus(), rsaJwk.getModulus().decodeToBigInteger());

    verify(jwtUtils, times(1)).getPublicKey();
    verify(jwtUtils, times(1)).getKeyId();
  }

}