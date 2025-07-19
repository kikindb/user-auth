package dev.kikin.user_auth.controllers;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import dev.kikin.user_auth.entity.RefreshToken;
import dev.kikin.user_auth.entity.Role;
import dev.kikin.user_auth.entity.User;
import dev.kikin.user_auth.exceptions.TokenRefreshException;
import dev.kikin.user_auth.payload.request.TokenRefreshRequest;
import dev.kikin.user_auth.payload.response.TokenRefreshResponse;
import dev.kikin.user_auth.repository.RoleRepository;
import dev.kikin.user_auth.repository.UserRepository;
import dev.kikin.user_auth.security.jwt.JwtUtils;
import dev.kikin.user_auth.security.services.UserDetailsImpl;
import dev.kikin.user_auth.payload.request.JwtResponse;
import dev.kikin.user_auth.payload.request.LoginRequest;
import dev.kikin.user_auth.payload.request.SignupRequest;
import dev.kikin.user_auth.payload.response.MessageResponse;
import dev.kikin.user_auth.services.RefreshTokenService;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * REST Controller for user authentication (signup, signin, and token refresh).
 * Handles requests to /api/auth/** endpoints.
 */
@CrossOrigin(origins = "*", maxAge = 3600) // Allows cross-origin requests for development
@RestController // Marks this class as a REST controller
@RequestMapping("/api/auth") // Base path for all endpoints in this controller
public class AuthController {

  @Autowired
  AuthenticationManager authenticationManager; // Manages authentication process

  @Autowired
  UserRepository userRepository; // Repository for User entity operations

  @Autowired
  RoleRepository roleRepository; // Repository for Role entity operations

  @Autowired
  PasswordEncoder encoder; // Encodes passwords (BCryptPasswordEncoder)

  @Autowired
  JwtUtils jwtUtils; // Utility for JWT operations

  @Autowired
  RefreshTokenService refreshTokenService; // Service for refresh token operations

  /**
   * Handles user sign-in requests.
   * Authenticates the user and returns a JWT access token and a refresh token upon successful authentication.
   *
   * @param loginRequest The request body containing username and password.
   * @return ResponseEntity with JwtResponse if successful, or error message.
   */
  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    // Authenticate the user using Spring Security's AuthenticationManager
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    // Set the authenticated user in the SecurityContextHolder
    SecurityContextHolder.getContext().setAuthentication(authentication);

    // Get UserDetails from the authentication object
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    // Generate a JWT access token for the authenticated user
    String jwt = jwtUtils.generateJwtToken(authentication);

    // Create and save a refresh token for the user
    RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

    // Extract roles from userDetails and convert them to a list of strings
    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    // Return the JWT response containing access token, refresh token, and user details
    return ResponseEntity.ok(new JwtResponse(jwt,
        refreshToken.getToken(), // Include refresh token
        userDetails.getId(),
        userDetails.getUsername(),
        userDetails.getEmail(),
        roles));
  }

  /**
   * Handles user registration (signup) requests.
   * Creates a new user with default or specified roles.
   *
   * @param signupRequest The request body containing username, email, password, and optional roles.
   * @return ResponseEntity with MessageResponse indicating success or failure.
   */
  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
    // Check if username already exists
    if (userRepository.existsByUsername(signupRequest.getUsername())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Username is already taken!"));
    }

    // Check if email already exists
    if (userRepository.existsByEmail(signupRequest.getEmail())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signupRequest.getUsername(),
        encoder.encode(signupRequest.getPassword()), // Encode password before saving
        signupRequest.getEmail());

    Set<String> strRoles = signupRequest.getRole();
    Set<Role> roles = new HashSet<>();

    // Assign roles based on the request, or default to "ROLE_USER"
    if (strRoles == null) {
      Role userRole = roleRepository.findByName("ROLE_USER")
          .orElseThrow(() -> new RuntimeException("Error: Role 'ROLE_USER' is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseThrow(() -> new RuntimeException("Error: Role 'ROLE_ADMIN' is not found."));
            roles.add(adminRole);
            break;
          case "mod":
            Role modRole = roleRepository.findByName("ROLE_MODERATOR")
                .orElseThrow(() -> new RuntimeException("Error: Role 'ROLE_MODERATOR' is not found."));
            roles.add(modRole);
            break;
          default:
            Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Error: Role 'ROLE_USER' is not found."));
            roles.add(userRole);
        }
      });
    }

    user.setRoles(roles); // Set the determined roles for the user
    userRepository.save(user); // Save the new user to the database

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  /**
   * Handles refresh token requests.
   * Exchanges a valid refresh token for a new JWT access token.
   *
   * @param request The request body containing the refresh token.
   * @return ResponseEntity with TokenRefreshResponse containing the new access token and the refresh token.
   */
  @PostMapping("/refreshtoken")
  public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
    String requestRefreshToken = request.getRefreshToken();

    return refreshTokenService.findByToken(requestRefreshToken)
        .map(refreshTokenService::verifyExpiration) // Verify if token is expired
        .map(RefreshToken::getUser) // Get the user associated with the refresh token
        .map(user -> {
          // Generate a new access token for the user
          String newAccessToken = jwtUtils.generateJwtToken(
              new UsernamePasswordAuthenticationToken(UserDetailsImpl.build(user), null, user.getRoles().stream()
                  .map(role -> new SimpleGrantedAuthority(role.getName()))
                  .collect(Collectors.toList()))
          );
          return ResponseEntity.ok(new TokenRefreshResponse(newAccessToken, requestRefreshToken, "Bearer"));
        })
        .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
            "Refresh token is not in database!"));
  }

  @GetMapping("/.well-known/jwks.json")
  public Map<String, Object> jwks() {
    RSAPublicKey publicKey = jwtUtils.getPublicKey();
    String keyId = jwtUtils.getKeyId();

    JWK jwk = new RSAKey.Builder(publicKey)
        .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE) // Uso de la clave: firma
        .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256) // Algoritmo de firma
        .keyID(keyId) // Establece el Key ID
        .build();

    return new JWKSet(jwk).toJSONObject();
  }
}