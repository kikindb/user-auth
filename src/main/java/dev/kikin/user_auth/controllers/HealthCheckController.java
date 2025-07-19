package dev.kikin.user_auth.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * REST Controller for health checking the application.
 * Provides a simple endpoint to verify if the service is up and running.
 */
@RestController // Marks this class as a REST controller
@RequestMapping("/health") // Base path for all endpoints in this controller
public class HealthCheckController {

  /**
   * Responds to health check requests.
   * Returns a simple JSON object indicating the application's status.
   *
   * @return ResponseEntity with a map containing the status.
   */
  @GetMapping
  public ResponseEntity<Map<String, String>> healthCheck() {
    Map<String, String> response = new HashMap<>();
    response.put("status", "UP"); // Indicate that the service is up
    response.put("message", "Auth Service is running successfully!");
    return ResponseEntity.ok(response);
  }
}
