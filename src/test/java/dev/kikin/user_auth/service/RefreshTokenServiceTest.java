package dev.kikin.user_auth.service;

import dev.kikin.user_auth.entity.RefreshToken;
import dev.kikin.user_auth.entity.Role;
import dev.kikin.user_auth.entity.User;
import dev.kikin.user_auth.exceptions.TokenRefreshException;
import dev.kikin.user_auth.repository.RefreshTokenRepository;
import dev.kikin.user_auth.repository.UserRepository;
import dev.kikin.user_auth.services.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RefreshTokenService class.
 * Tests creation, verification, and deletion of refresh tokens.
 */
@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

  @Mock // Mocks the RefreshTokenRepository dependency
  private RefreshTokenRepository refreshTokenRepository;

  @Mock // Mocks the UserRepository dependency
  private UserRepository userRepository;

  @InjectMocks // Injects the mocks into RefreshTokenService instance
  private RefreshTokenService refreshTokenService;

  private User testUser;
  private Long refreshTokenDurationMs = 86400000L; // 24 hours in milliseconds

  @BeforeEach
  void setUp() {
    // Initialize a test user
    testUser = new User("testuser", "password", "test@example.com");
    testUser.setId(1L);
    testUser.setRoles(Collections.singleton(new Role("ROLE_USER"))); // Assign a role

    // Inject the refresh token duration property
    ReflectionTestUtils.setField(refreshTokenService, "refreshTokenDurationMs", refreshTokenDurationMs);
  }

  @Test
  @DisplayName("Should find a refresh token by its token string")
  void findByToken_shouldReturnRefreshToken() {
    // Arrange
    RefreshToken refreshToken = new RefreshToken(1L, testUser, "some-token", Instant.now().plusMillis(refreshTokenDurationMs));
    when(refreshTokenRepository.findByToken("some-token")).thenReturn(Optional.of(refreshToken));

    // Act
    Optional<RefreshToken> foundToken = refreshTokenService.findByToken("some-token");

    // Assert
    assertTrue(foundToken.isPresent());
    assertEquals("some-token", foundToken.get().getToken());
    verify(refreshTokenRepository, times(1)).findByToken("some-token");
  }

  @Test
  @DisplayName("Should create a new refresh token if none exists for the user")
  void createRefreshToken_shouldCreateNewToken() {
    // Arrange
    when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
    when(refreshTokenRepository.findByUser(testUser)).thenReturn(Optional.empty()); // No existing token
    when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0)); // Return the saved token

    // Act
    RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(testUser.getId());

    // Assert
    assertNotNull(newRefreshToken);
    assertNotNull(newRefreshToken.getToken());
    assertEquals(testUser, newRefreshToken.getUser());
    assertTrue(newRefreshToken.getExpiryDate().isAfter(Instant.now()));
    verify(refreshTokenRepository, times(1)).findByUser(testUser);
    verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
  }

  @Test
  @DisplayName("Should update an existing refresh token for the user")
  void createRefreshToken_shouldUpdateExistingToken() {
    // Arrange
    RefreshToken existingRefreshToken = new RefreshToken(2L, testUser, "old-token", Instant.now().minusSeconds(3600)); // An old token
    when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
    when(refreshTokenRepository.findByUser(testUser)).thenReturn(Optional.of(existingRefreshToken)); // Existing token
    when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0)); // Return the saved token

    // Act
    RefreshToken updatedRefreshToken = refreshTokenService.createRefreshToken(testUser.getId());

    // Assert
    assertNotNull(updatedRefreshToken);
    assertNotEquals("old-token", updatedRefreshToken.getToken()); // Token string should be updated
    assertTrue(updatedRefreshToken.getExpiryDate().isAfter(Instant.now())); // Expiry date should be updated
    assertEquals(existingRefreshToken.getId(), updatedRefreshToken.getId()); // Should be the same entity ID
    verify(refreshTokenRepository, times(1)).findByUser(testUser);
    verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
  }

  @Test
  @DisplayName("Should throw RuntimeException if user not found during token creation")
  void createRefreshToken_shouldThrowExceptionIfUserNotFound() {
    // Arrange
    when(userRepository.findById(anyLong())).thenReturn(Optional.empty());

    // Act & Assert
    RuntimeException exception = assertThrows(RuntimeException.class,
        () -> refreshTokenService.createRefreshToken(99L));
    assertEquals("User not found for refresh token creation.", exception.getMessage());
    verify(userRepository, times(1)).findById(99L);
    verify(refreshTokenRepository, never()).findByUser(any());
    verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
  }

  @Test
  @DisplayName("Should return the token if it is not expired")
  void verifyExpiration_shouldReturnTokenIfNotExpired() {
    // Arrange
    RefreshToken refreshToken = new RefreshToken(1L, testUser, "valid-token", Instant.now().plusMillis(10000)); // 10 seconds from now

    // Act
    RefreshToken result = refreshTokenService.verifyExpiration(refreshToken);

    // Assert
    assertEquals(refreshToken, result);
    verify(refreshTokenRepository, never()).delete(any(RefreshToken.class)); // Should not delete
  }

  @Test
  @DisplayName("Should throw TokenRefreshException and delete token if it is expired")
  void verifyExpiration_shouldThrowExceptionAnd_deleteTokenIfExpired() {
    // Arrange
    RefreshToken refreshToken = new RefreshToken(1L, testUser, "expired-token", Instant.now().minusMillis(1000)); // 1 second ago

    // Act & Assert
    TokenRefreshException exception = assertThrows(TokenRefreshException.class,
        () -> refreshTokenService.verifyExpiration(refreshToken));

    assertEquals("Failed for [expired-token]: Refresh token was expired. Please make a new signin request", exception.getMessage());
    verify(refreshTokenRepository, times(1)).delete(refreshToken); // Should delete
  }

  @Test
  @DisplayName("Should delete refresh token by user ID")
  void deleteByUserId_shouldDeleteToken() {
    // Arrange
    when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
    when(refreshTokenRepository.deleteByUser(testUser)).thenReturn(1); // Simulate 1 token deleted

    // Act
    int deletedCount = refreshTokenService.deleteByUserId(testUser.getId());

    // Assert
    assertEquals(1, deletedCount);
    verify(userRepository, times(1)).findById(testUser.getId());
    verify(refreshTokenRepository, times(1)).deleteByUser(testUser);
  }

  @Test
  @DisplayName("Should throw RuntimeException if user not found during token deletion")
  void deleteByUserId_shouldThrowExceptionIfUserNotFound() {
    // Arrange
    when(userRepository.findById(anyLong())).thenReturn(Optional.empty());

    // Act & Assert
    RuntimeException exception = assertThrows(RuntimeException.class,
        () -> refreshTokenService.deleteByUserId(99L));
    assertEquals("User not found for deleting refresh token.", exception.getMessage());
    verify(userRepository, times(1)).findById(99L);
    verify(refreshTokenRepository, never()).deleteByUser(any());
  }
}