package dev.kikin.user_auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "permissions")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Permission {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY) // Auto-increments the ID
  private Long id;

  @Column(nullable = false, unique = true) // Permission name must be unique and not null
  private String name; // e.g., "READ_USER", "WRITE_PRODUCT"

  /**
   * Constructor for creating a new Permission.
   * @param name The name of the permission (e.g., "READ_USER").
   */
  public Permission(String name) {
    this.name = name;
  }
}
