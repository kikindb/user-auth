package dev.kikin.user_auth.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.Instant;

/**
 * Represents a Refresh Token in the authentication system.
 * This entity will be mapped to a 'refresh_tokens' table in the PostgreSQL database.
 */
@Entity
@Table(name = "refresh_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @OneToOne // One-to-one relationship with User
  @JoinColumn(name = "user_id", referencedColumnName = "id") // Foreign key to the users table
  private User user;

  @Column(nullable = false, unique = true) // Refresh token string must be unique and not null
  private String token;

  @Column(nullable = false) // Expiry date must not be null
  private Instant expiryDate;

  /**
   * Checks if the refresh token has expired.
   * @return true if the token has expired, false otherwise.
   */
  public boolean isExpired() {
    return this.expiryDate.isBefore(Instant.now());
  }
}
