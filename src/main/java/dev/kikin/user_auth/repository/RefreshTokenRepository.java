package dev.kikin.user_auth.repository;

import dev.kikin.user_auth.entity.RefreshToken;
import dev.kikin.user_auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;


/**
 * Repository interface for RefreshToken entity.
 * Provides standard CRUD operations and custom query methods.
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

  /**
   * Finds a RefreshToken by its token string.
   * @param token The refresh token string to search for.
   * @return An Optional containing the RefreshToken if found, or empty otherwise.
   */
  Optional<RefreshToken> findByToken(String token);

  /**
   * Finds a RefreshToken by the associated User.
   * This is crucial for the one-to-one relationship.
   * @param user The User entity.
   * @return An Optional containing the RefreshToken if found, or empty otherwise.
   */
  Optional<RefreshToken> findByUser(User user);

  /**
   * Deletes refresh tokens associated with a specific user.
   * @param user The user whose refresh tokens should be deleted.
   * @return The number of deleted refresh tokens.
   */
  @Modifying // Indicates that this query modifies the database
  @Transactional // Added @Transactional to ensure the delete operation runs within a transaction
  int deleteByUser(User user);
}