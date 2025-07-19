package dev.kikin.user_auth.utils;

import dev.kikin.user_auth.entity.Role;
import dev.kikin.user_auth.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A CommandLineRunner that initializes default roles in the database on application startup.
 * This ensures that roles like "ROLE_USER", "ROLE_MODERATOR", and "ROLE_ADMIN" exist
 * before users can be registered with these roles.
 */
@Component // Marks this class as a Spring component to be managed by the Spring container
public class RoleInitializer implements CommandLineRunner {

  private static final Logger logger = LoggerFactory.getLogger(RoleInitializer.class);

  private final RoleRepository roleRepository;

  // Constructor injection for RoleRepository
  public RoleInitializer(RoleRepository roleRepository) {
    this.roleRepository = roleRepository;
  }

  /**
   * This method is executed automatically by Spring Boot after the application context is loaded.
   * It checks for the existence of predefined roles and creates them if they don't exist.
   *
   * @param args Command line arguments (not used in this case).
   * @throws Exception If an error occurs during role initialization.
   */
  @Override
  public void run(String... args) throws Exception {
    // Define the roles we want to ensure exist
    String[] rolesToInitialize = {"ROLE_USER", "ROLE_MODERATOR", "ROLE_ADMIN"};

    logger.info("Checking and initializing default roles...");

    for (String roleName : rolesToInitialize) {
      // Check if the role already exists in the database
      if (roleRepository.findByName(roleName).isEmpty()) {
        // If the role does not exist, create a new Role entity
        Role newRole = new Role(roleName);
        // Save the new role to the database
        roleRepository.save(newRole);
        logger.info("Created role: {}", roleName);
      } else {
        logger.info("Role '{}' already exists.", roleName);
      }
    }
    logger.info("Role initialization complete.");
  }
}
