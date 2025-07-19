package dev.kikin.user_auth.payload.response;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * DTO for refresh token response.
 * Contains the new access token and the refresh token.
 */
@Data // Lombok annotation to generate getters, setters, toString, equals, and hashCode
@NoArgsConstructor // Lombok annotation to generate a no-argument constructor
@AllArgsConstructor // Lombok annotation to generate an all-argument constructor
public class TokenRefreshResponse {
  private String accessToken;
  private String refreshToken;
  private String tokenType = "Bearer"; // Default token type

  // Explicit constructor to match the AuthController's usage
  public TokenRefreshResponse(String accessToken, String refreshToken) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.tokenType = "Bearer"; // Default to Bearer if not explicitly provided
  }
}