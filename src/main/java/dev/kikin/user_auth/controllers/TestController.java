package dev.kikin.user_auth.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A simple REST Controller for testing secured endpoints based on roles.
 */
@CrossOrigin(origins = "*", maxAge = 3600) // Allows cross-origin requests for development
@RestController // Marks this class as a REST controller
@RequestMapping("/api/test") // Base path for all endpoints in this controller
public class TestController {

  /**
   * Accessible by anyone (authenticated or not).
   */
  @GetMapping("/all")
  public String allAccess() {
    return "Public Content.";
  }

  /**
   * Accessible only by authenticated users (any role).
   */
  @GetMapping("/user")
  @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_MODERATOR') or hasRole('ROLE_ADMIN')")
  public String userAccess() {
    return "User Content.";
  }

  /**
   * Accessible only by users with the "MODERATOR" role.
   */
  @GetMapping("/mod")
  @PreAuthorize("hasRole('ROLE_MODERATOR') or hasRole('ROLE_ADMIN')")
  public String moderatorAccess() {
    return "Moderator Board.";
  }

  /**
   * Accessible only by users with the "ADMIN" role.
   */
  @GetMapping("/admin")
  @PreAuthorize("hasRole('ADMIN')")
  public String adminAccess() {
    return "Admin Board.";
  }
}
