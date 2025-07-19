package dev.kikin.user_auth.services;

import dev.kikin.user_auth.entity.RefreshToken;
import dev.kikin.user_auth.entity.User;
import dev.kikin.user_auth.exceptions.TokenRefreshException;
import dev.kikin.user_auth.repository.RefreshTokenRepository;
import dev.kikin.user_auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Service for managing Refresh Tokens.
 * Handles creation, verification, and deletion of refresh tokens.
 */
@Service
public class RefreshTokenService {

  @Value("${auth.app.jwtRefreshExpirationMs}")
  private Long refreshTokenDurationMs; // Expiration time for refresh tokens

  @Autowired
  private RefreshTokenRepository refreshTokenRepository;

  @Autowired
  private UserRepository userRepository;

  /**
   * Finds a refresh token by its string value.
   * @param token The refresh token string.
   * @return An Optional containing the RefreshToken entity.
   */
  public Optional<RefreshToken> findByToken(String token) {
    return refreshTokenRepository.findByToken(token);
  }

  /**
   * Creates or updates a refresh token for a given user.
   * If a refresh token already exists for the user, it updates its token string and expiry date.
   * If not, it creates a new one.
   *
   * @param userId The ID of the user.
   * @return The created or updated RefreshToken entity.
   */
  @Transactional // Ensures this method runs within a transaction
  public RefreshToken createRefreshToken(Long userId) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found for refresh token creation."));

    Optional<RefreshToken> existingToken = refreshTokenRepository.findByUser(user);
    RefreshToken refreshToken;

    if (existingToken.isPresent()) {
      // Update existing token
      refreshToken = existingToken.get();
      refreshToken.setToken(UUID.randomUUID().toString()); // Generate a new random UUID
      refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs)); // Update expiry date
    } else {
      // Create new token
      refreshToken = new RefreshToken();
      refreshToken.setUser(user);
      refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
      refreshToken.setToken(UUID.randomUUID().toString());
    }

    refreshToken = refreshTokenRepository.save(refreshToken); // Save or update to database
    return refreshToken;
  }

  /**
   * Verifies if a refresh token is valid (not expired).
   *
   * @param token The RefreshToken entity to verify.
   * @return The verified RefreshToken entity.
   * @throws TokenRefreshException if the token is expired.
   */
  public RefreshToken verifyExpiration(RefreshToken token) {
    if (token.getExpiryDate().isBefore(Instant.now())) {
      refreshTokenRepository.delete(token); // Delete expired token from database
      throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
    }
    return token;
  }

  /**
   * Deletes a refresh token associated with a specific user.
   * @param userId The ID of the user.
   * @return The number of deleted refresh tokens.
   */
  @Transactional // Ensures the operation is atomic
  public int deleteByUserId(Long userId) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found for deleting refresh token."));
    return refreshTokenRepository.deleteByUser(user);
  }
}