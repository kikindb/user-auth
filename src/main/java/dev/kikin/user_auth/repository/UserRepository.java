package dev.kikin.user_auth.repository;

import dev.kikin.user_auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
  /**
   * Finds a User by their username.
   * @param username The username to search for.
   * @return An Optional containing the User if found, or empty otherwise.
   */
  Optional<User> findByUsername(String username);

  /**
   * Checks if a User with the given username exists.
   * @param username The username to check.
   * @return True if a user with this username exists, false otherwise.
   */
  Boolean existsByUsername(String username);

  /**
   * Checks if a User with the given email exists.
   * @param email The email to check.
   * @return True if a user with this email exists, false otherwise.
   */
  Boolean existsByEmail(String email);
}
