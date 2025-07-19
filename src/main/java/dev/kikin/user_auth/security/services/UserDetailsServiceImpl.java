package dev.kikin.user_auth.security.services;

import dev.kikin.user_auth.entity.User;
import dev.kikin.user_auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired // Injects the UserRepository to fetch user data
  UserRepository userRepository;

  /**
   * Loads user details by username. This method is called by Spring Security
   * during the authentication process to retrieve user information from the database.
   *
   * @param username The username of the user to load.
   * @return A UserDetails object containing the user's information and authorities.
   * @throws UsernameNotFoundException If the user with the given username is not found.
   */
  @Override
  @Transactional // Ensures the entire method runs within a single transaction
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    // Find the user by username in the database
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    // Build and return a UserDetailsImpl object from the retrieved User entity
    return UserDetailsImpl.build(user);
  }
}
