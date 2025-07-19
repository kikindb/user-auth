package dev.kikin.user_auth.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * DTO for refresh token requests.
 * Contains the refresh token string.
 */
@Data // Lombok annotation to generate getters, setters, toString, equals, and hashCode
@NoArgsConstructor // Lombok annotation to generate a no-argument constructor
@AllArgsConstructor // Lombok annotation to generate an all-argument constructor
public class TokenRefreshRequest {
  @NotBlank // Ensures the refreshToken field is not null and not empty
  private String refreshToken;
}
