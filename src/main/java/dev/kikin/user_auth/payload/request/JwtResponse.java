package dev.kikin.user_auth.payload.request;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO for JWT authentication response.
 * Contains the JWT token, user ID, username, email, and a list of roles.
 */
@Data // Lombok annotation to generate getters, setters, toString, equals, and hashCode
@NoArgsConstructor // Lombok annotation to generate a no-argument constructor
public class JwtResponse {
  private String token;
  private String type = "Bearer"; // Default token type
  private Long id;
  private String username;
  private String email;
  private List<String> roles; // List of roles (e.g., "ROLE_USER", "ROLE_ADMIN")

  /**
   * Constructor for JwtResponse.
   * @param accessToken The generated JWT token.
   * @param id The user's ID.
   * @param username The user's username.
   * @param email The user's email.
   * @param roles A list of the user's roles.
   */
  public JwtResponse(String accessToken, Long id, String username, String email, List<String> roles) {
    this.token = accessToken;
    this.id = id;
    this.username = username;
    this.email = email;
    this.roles = roles;
  }
}
