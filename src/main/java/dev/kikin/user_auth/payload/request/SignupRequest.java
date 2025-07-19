package dev.kikin.user_auth.payload.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.util.Set;

/**
 * DTO for user registration requests.
 * Contains username, email, password, and optional roles, with validation annotations.
 */
@Data // Lombok annotation to generate getters, setters, toString, equals, and hashCode
@NoArgsConstructor // Lombok annotation to generate a no-argument constructor
@AllArgsConstructor // Lombok annotation to generate an all-argument constructor
public class SignupRequest {
  @NotBlank // Ensures the username field is not null and not empty
  @Size(min = 3, max = 20) // Specifies minimum and maximum size for username
  private String username;

  @NotBlank // Ensures the email field is not null and not empty
  @Size(max = 50) // Specifies maximum size for email
  @Email // Ensures the email is in a valid email format
  private String email;

  @NotBlank // Ensures the password field is not null and not empty
  @Size(min = 6, max = 40) // Specifies minimum and maximum size for password
  private String password;

  // Optional set of roles for the user (e.g., "admin", "mod", "user")
  private Set<String> role;
}
