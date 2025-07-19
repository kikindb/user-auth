package dev.kikin.user_auth.repository;

import dev.kikin.user_auth.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
  /**
   * Finds a Permission by its name.
   * @param name The name of the permission to search for (e.g., "READ_USER").
   * @return An Optional containing the Permission if found, or empty otherwise.
   */
  Optional<Role> findByName(String name);
}
