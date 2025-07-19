package dev.kikin.user_auth.security.services;

import dev.kikin.user_auth.entity.User;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.ArrayList; // Added import

/**
 * Custom implementation of Spring Security's UserDetails interface.
 * This class wraps our User entity and provides the necessary details
 * (username, password, authorities) for Spring Security to perform authentication and authorization.
 */
public class UserDetailsImpl implements UserDetails {
  private static final long serialVersionUID = 1L;

  private Long id;
  private String username;
  private String email;

  @JsonIgnore // Prevents password from being serialized to JSON
  private String password;

  // Collection of authorities (roles and permissions) granted to the user
  private Collection<? extends GrantedAuthority> authorities;

  /**
   * Constructor for UserDetailsImpl.
   *
   * @param id The user's ID.
   * @param username The user's username.
   * @param email The user's email.
   * @param password The user's hashed password.
   * @param authorities A collection of GrantedAuthority objects (roles/permissions).
   */
  public UserDetailsImpl(Long id, String username, String email, String password,
                         Collection<? extends GrantedAuthority> authorities) {
    this.id = id;
    this.username = username;
    this.email = email;
    this.password = password;
    this.authorities = authorities;
  }

  /**
   * Builds a UserDetailsImpl object from a User entity.
   * This method maps the User's roles and their associated permissions to Spring Security's GrantedAuthority.
   *
   * @param user The User entity.
   * @return A new UserDetailsImpl instance.
   */
  public static UserDetailsImpl build(User user) {
    List<GrantedAuthority> authorities = new ArrayList<>();

    // Add roles with "ROLE_" prefix
    user.getRoles().forEach(role ->
        authorities.add(new SimpleGrantedAuthority(role.getName())) // Assuming role.getName() already has "ROLE_" prefix
    );

    // Add permissions
    user.getRoles().forEach(role ->
        role.getPermissions().stream()
            .map(permission -> new SimpleGrantedAuthority(permission.getName()))
            .forEach(authorities::add)
    );

    return new UserDetailsImpl(
        user.getId(),
        user.getUsername(),
        user.getEmail(),
        user.getPassword(),
        authorities);
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return username;
  }

  public Long getId() {
    return id;
  }

  public String getEmail() {
    return email;
  }

  // Account status methods (we'll keep them true for now)
  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  // Custom equals and hashCode for comparison
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    UserDetailsImpl user = (UserDetailsImpl) o;
    return Objects.equals(id, user.id);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id);
  }
}