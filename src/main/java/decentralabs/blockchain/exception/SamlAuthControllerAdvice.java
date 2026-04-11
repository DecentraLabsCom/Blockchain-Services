package decentralabs.blockchain.exception;

import decentralabs.blockchain.controller.auth.SamlAuthController;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = SamlAuthController.class)
@Slf4j
public class SamlAuthControllerAdvice {

    @ExceptionHandler({
        SamlExpiredAssertionException.class,
        SamlInvalidIssuerException.class,
        SamlReplayAttackException.class,
        SecurityException.class
    })
    public ResponseEntity<Map<String, Object>> handleUnauthorized(Exception ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler({
        SamlMalformedResponseException.class,
        SamlMissingAttributesException.class,
        IllegalArgumentException.class
    })
    public ResponseEntity<Map<String, Object>> handleBadRequest(Exception ex) {
        return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(SamlServiceUnavailableException.class)
    public ResponseEntity<Map<String, Object>> handleServiceUnavailable(SamlServiceUnavailableException ex) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception ex) {
        log.error("SAML authentication error", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(Map.of("error", "Internal server error"));
    }
}
