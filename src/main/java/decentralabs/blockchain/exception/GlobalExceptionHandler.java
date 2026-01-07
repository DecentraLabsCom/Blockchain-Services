package decentralabs.blockchain.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler for all controllers
 * Provides centralized, consistent error handling
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Determine if request expects JSON response (API request)
     */
    private boolean isApiRequest(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        String contentType = request.getContentType();
        String path = request.getRequestURI();
        
        // API endpoints or explicit JSON requests
        if (path != null && (path.startsWith("/api/") || path.contains("/status"))) {
            return true;
        }
        // WebAuthn onboarding endpoints (except ceremony HTML page) expect JSON
        if (path != null && path.startsWith("/onboarding/webauthn/") && !path.contains("/ceremony/")) {
            return true;
        }
        // Intent endpoints expect JSON
        if (path != null && path.startsWith("/intents")) {
            return true;
        }
        // Wallet endpoints expect JSON
        if (path != null && path.startsWith("/wallet/")) {
            return true;
        }
        if (accept != null && accept.contains("application/json")) {
            return true;
        }
        if (contentType != null && contentType.contains("application/json")) {
            return true;
        }
        // XHR requests typically expect JSON
        if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
            return true;
        }
        return false;
    }

    /**
     * Handles ResponseStatusException (thrown by controllers/services)
     * This ensures JSON responses instead of HTML error pages for API endpoints.
     */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handleResponseStatusException(
            ResponseStatusException ex, HttpServletRequest request) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", ex.getReason() != null ? ex.getReason() : ex.getStatusCode().toString());
        response.put("status", ex.getStatusCode().value());

        log.warn("ResponseStatusException at {}: {} - {}", 
            request.getRequestURI(), ex.getStatusCode(), ex.getReason());
        return ResponseEntity.status(ex.getStatusCode()).body(response);
    }

    /**
     * Handles validation errors from @Valid annotations
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", "Validation failed");
        response.put("errors", errors);

        log.warn("Validation error: {}", errors);
        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handles illegal argument exceptions
     */
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<Map<String, Object>> handleIllegalArgumentException(
            IllegalArgumentException ex) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", ex.getMessage());

        log.warn("Invalid argument: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handles security exceptions
     */
    @ExceptionHandler(SecurityException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<Map<String, Object>> handleSecurityException(
            SecurityException ex) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", ex.getMessage());

        log.error("Security exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    /**
     * Handles wallet operation exceptions
     */
    @ExceptionHandler(WalletOperationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<Map<String, Object>> handleWalletOperationException(
            WalletOperationException ex) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", ex.getMessage());
        response.put("operation", ex.getOperation());

        log.error("Wallet operation failed [{}]: {}", ex.getOperation(), ex.getMessage());
        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handles blockchain exceptions
     */
    @ExceptionHandler(BlockchainException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ResponseEntity<Map<String, Object>> handleBlockchainException(
            BlockchainException ex) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", "Blockchain service temporarily unavailable");
        response.put("details", ex.getMessage());

        log.error("Blockchain error: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }

    /**
     * Handles all other exceptions
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Object handleGenericException(
            Exception ex, HttpServletRequest request) {
        
        log.error("Unexpected error at {}: {}", request.getRequestURI(), ex.getMessage(), ex);

        // For non-API requests (HTML pages), rethrow to let Spring handle error page
        if (!isApiRequest(request)) {
            // Return error view or rethrow for default error handling
            ModelAndView mav = new ModelAndView("error");
            mav.addObject("error", "An unexpected error occurred");
            mav.addObject("status", 500);
            mav.setStatus(HttpStatus.INTERNAL_SERVER_ERROR);
            return mav;
        }

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", "An unexpected error occurred");

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
