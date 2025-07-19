package dev.kikin.user_auth.repository;

import dev.kikin.user_auth.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PermissionRepository extends JpaRepository<Role, Long> {
  /**
   * Finds a Role by its name.
   * @param name The name of the role to search for (e.g., "ROLE_USER").
   * @return An Optional containing the Role if found, or empty otherwise.
   */
  Optional<Role> findByName(String name);
}
