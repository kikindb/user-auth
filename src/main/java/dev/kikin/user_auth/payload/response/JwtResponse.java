package dev.kikin.user_auth.payload.response;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO for JWT authentication response.
 * Contains the JWT token, user ID, username, email, roles, and refresh token.
 */
@Data // Lombok annotation to generate getters, setters, toString, equals, and hashCode
@NoArgsConstructor // Lombok annotation to generate a no-argument constructor
public class JwtResponse {
  private String accessToken; // Renamed for clarity (was 'token')
  private String refreshToken; // New field for refresh token
  private String type = "Bearer"; // Default token type
  private Long id;
  private String username;
  private String email;
  private List<String> roles; // List of roles (e.g., "ROLE_USER", "ROLE_ADMIN")

  /**
   * Constructor for JwtResponse.
   * @param accessToken The generated JWT access token.
   * @param refreshToken The generated refresh token.
   * @param id The user's ID.
   * @param username The user's username.
   * @param email The user's email.
   * @param roles A list of the user's roles.
   */
  public JwtResponse(String accessToken, String refreshToken, Long id, String username, String email, List<String> roles) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.id = id;
    this.username = username;
    this.email = email;
    this.roles = roles;
  }
}
