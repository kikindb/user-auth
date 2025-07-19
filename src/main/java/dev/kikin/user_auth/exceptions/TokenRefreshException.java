package dev.kikin.user_auth.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom exception for refresh token related errors (e.g., token expired).
 * Returns a 403 Forbidden status.
 */
@ResponseStatus(HttpStatus.FORBIDDEN) // Sets the HTTP status code for this exception
public class TokenRefreshException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  /**
   * Constructor for TokenRefreshException.
   * @param token The invalid refresh token.
   * @param message The error message.
   */
  public TokenRefreshException(String token, String message) {
    super(String.format("Failed for [%s]: %s", token, message));
  }
}
