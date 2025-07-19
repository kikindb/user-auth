package dev.kikin.user_auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY) // Auto-increments the ID
  private Long id;

  @Column(nullable = false, unique = true) // Username must be unique and not null
  private String username;

  @Column(nullable = false) // Password must not be null
  private String password; // Store hashed passwords, not plain text!

  @Column(nullable = false, unique = true) // Email must be unique and not null
  private String email;

  @ManyToMany(fetch = FetchType.EAGER) // Many-to-many relationship with Role, eager fetching to load roles with user
  @JoinTable(
      name = "user_roles", // Junction table name
      joinColumns = @JoinColumn(name = "user_id"), // Column in junction table referring to User
      inverseJoinColumns = @JoinColumn(name = "role_id") // Column in junction table referring to Role
  )
  private Set<Role> roles = new HashSet<>(); // Initialize to prevent NullPointerExceptions

  /**
   * Constructor for creating a new User.
   * @param username The user's chosen username.
   * @param password The user's hashed password.
   * @param email The user's email address.
   */
  public User(String username, String password, String email) {
    this.username = username;
    this.password = password;
    this.email = email;
  }
}
