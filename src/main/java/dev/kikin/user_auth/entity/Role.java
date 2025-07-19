package dev.kikin.user_auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Role {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY) // Auto-increments the ID
  private Long id;

  @Column(nullable = false, unique = true) // Role name must be unique and not null
  private String name; // e.g., "ROLE_USER", "ROLE_ADMIN"

  @ManyToMany(fetch = FetchType.EAGER) // Many-to-many relationship with Permission, eager fetching
  @JoinTable(
      name = "role_permissions", // Junction table name
      joinColumns = @JoinColumn(name = "role_id"), // Column in junction table referring to Role
      inverseJoinColumns = @JoinColumn(name = "permission_id") // Column in junction table referring to Permission
  )
  private Set<Permission> permissions = new HashSet<>(); // Initialize to prevent NullPointerExceptions

  /**
   * Constructor for creating a new Role.
   * @param name The name of the role (e.g., "ROLE_USER").
   */
  public Role(String name) {
    this.name = name;
  }
}
