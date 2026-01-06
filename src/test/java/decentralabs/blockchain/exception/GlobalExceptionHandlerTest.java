package decentralabs.blockchain.exception;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

@DisplayName("GlobalExceptionHandler Tests")
class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler();
        request = mock(HttpServletRequest.class);
    }

    @Nested
    @DisplayName("Validation Exception Tests")
    class ValidationExceptionTests {

        @Test
        @DisplayName("Should return 400 with validation errors")
        void shouldReturn400WithValidationErrors() {
            MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
            BindingResult bindingResult = mock(BindingResult.class);
            
            FieldError fieldError = new FieldError("object", "email", "must be a valid email");
            when(ex.getBindingResult()).thenReturn(bindingResult);
            when(bindingResult.getAllErrors()).thenReturn(java.util.List.of(fieldError));

            ResponseEntity<Map<String, Object>> response = handler.handleValidationExceptions(ex);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(false, response.getBody().get("success"));
            assertEquals("Validation failed", response.getBody().get("message"));
            
            @SuppressWarnings("unchecked")
            Map<String, String> errors = (Map<String, String>) response.getBody().get("errors");
            assertEquals("must be a valid email", errors.get("email"));
        }

        @Test
        @DisplayName("Should handle multiple validation errors")
        void shouldHandleMultipleValidationErrors() {
            MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
            BindingResult bindingResult = mock(BindingResult.class);
            
            FieldError error1 = new FieldError("object", "email", "must be a valid email");
            FieldError error2 = new FieldError("object", "password", "must be at least 8 characters");
            
            when(ex.getBindingResult()).thenReturn(bindingResult);
            when(bindingResult.getAllErrors()).thenReturn(java.util.List.of(error1, error2));

            ResponseEntity<Map<String, Object>> response = handler.handleValidationExceptions(ex);

            @SuppressWarnings("unchecked")
            Map<String, String> errors = (Map<String, String>) response.getBody().get("errors");
            assertEquals(2, errors.size());
            assertTrue(errors.containsKey("email"));
            assertTrue(errors.containsKey("password"));
        }
    }

    @Nested
    @DisplayName("IllegalArgumentException Tests")
    class IllegalArgumentExceptionTests {

        @Test
        @DisplayName("Should return 400 with error message")
        void shouldReturn400WithMessage() {
            IllegalArgumentException ex = new IllegalArgumentException("Invalid wallet address");

            ResponseEntity<Map<String, Object>> response = handler.handleIllegalArgumentException(ex);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(false, response.getBody().get("success"));
            assertEquals("Invalid wallet address", response.getBody().get("message"));
        }

        @Test
        @DisplayName("Should handle null message")
        void shouldHandleNullMessage() {
            IllegalArgumentException ex = new IllegalArgumentException((String) null);

            ResponseEntity<Map<String, Object>> response = handler.handleIllegalArgumentException(ex);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertNull(response.getBody().get("message"));
        }
    }

    @Nested
    @DisplayName("SecurityException Tests")
    class SecurityExceptionTests {

        @Test
        @DisplayName("Should return 403 for security violations")
        void shouldReturn403ForSecurityViolation() {
            SecurityException ex = new SecurityException("Access denied");

            ResponseEntity<Map<String, Object>> response = handler.handleSecurityException(ex);

            assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(false, response.getBody().get("success"));
            assertEquals("Access denied", response.getBody().get("message"));
        }

        @Test
        @DisplayName("Should handle unauthorized wallet access")
        void shouldHandleUnauthorizedWallet() {
            SecurityException ex = new SecurityException("Wallet not authorized for this operation");

            ResponseEntity<Map<String, Object>> response = handler.handleSecurityException(ex);

            assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
            assertEquals("Wallet not authorized for this operation", response.getBody().get("message"));
        }
    }

    @Nested
    @DisplayName("WalletOperationException Tests")
    class WalletOperationExceptionTests {

        @Test
        @DisplayName("Should return 400 with operation info")
        void shouldReturn400WithOperationInfo() {
            WalletOperationException ex = new WalletOperationException("CREATE", "Failed to generate key pair");

            ResponseEntity<Map<String, Object>> response = handler.handleWalletOperationException(ex);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(false, response.getBody().get("success"));
            assertEquals("Failed to generate key pair", response.getBody().get("message"));
            assertEquals("CREATE", response.getBody().get("operation"));
        }

        @Test
        @DisplayName("Should handle import operation failure")
        void shouldHandleImportFailure() {
            WalletOperationException ex = new WalletOperationException("IMPORT", "Invalid private key format");

            ResponseEntity<Map<String, Object>> response = handler.handleWalletOperationException(ex);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertEquals("IMPORT", response.getBody().get("operation"));
        }

        @Test
        @DisplayName("Should handle decrypt operation failure")
        void shouldHandleDecryptFailure() {
            WalletOperationException ex = new WalletOperationException("DECRYPT", "Wrong password");

            ResponseEntity<Map<String, Object>> response = handler.handleWalletOperationException(ex);

            assertEquals("DECRYPT", response.getBody().get("operation"));
            assertEquals("Wrong password", response.getBody().get("message"));
        }
    }

    @Nested
    @DisplayName("BlockchainException Tests")
    class BlockchainExceptionTests {

        @Test
        @DisplayName("Should return 503 for blockchain errors")
        void shouldReturn503ForBlockchainError() {
            BlockchainException ex = new BlockchainException("RPC node unavailable");

            ResponseEntity<Map<String, Object>> response = handler.handleBlockchainException(ex);

            assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(false, response.getBody().get("success"));
            assertEquals("Blockchain service temporarily unavailable", response.getBody().get("message"));
            assertEquals("RPC node unavailable", response.getBody().get("details"));
        }

        @Test
        @DisplayName("Should handle contract interaction failure")
        void shouldHandleContractFailure() {
            BlockchainException ex = new BlockchainException("Contract call reverted");

            ResponseEntity<Map<String, Object>> response = handler.handleBlockchainException(ex);

            assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
            assertEquals("Contract call reverted", response.getBody().get("details"));
        }
    }

    @Nested
    @DisplayName("Generic Exception Tests")
    class GenericExceptionTests {

        @Test
        @DisplayName("Should return 500 for unexpected errors")
        void shouldReturn500ForUnexpectedError() {
            Exception ex = new RuntimeException("Something went wrong");

            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>) handler.handleGenericException(ex, request);

            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
            assertNotNull(response.getBody());
            assertEquals(false, response.getBody().get("success"));
            assertEquals("An unexpected error occurred", response.getBody().get("message"));
            // Should NOT expose internal error details
            assertFalse(response.getBody().containsKey("details"));
        }

        @Test
        @DisplayName("Should not expose stack trace in response")
        void shouldNotExposeStackTrace() {
            Exception ex = new NullPointerException("Internal NPE");

            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>) handler.handleGenericException(ex, request);

            assertFalse(response.getBody().toString().contains("NullPointerException"));
            assertFalse(response.getBody().toString().contains("Internal NPE"));
        }

        @Test
        @DisplayName("Should handle nested exceptions")
        void shouldHandleNestedException() {
            Exception cause = new IllegalStateException("Root cause");
            Exception ex = new RuntimeException("Wrapper exception", cause);

            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>) handler.handleGenericException(ex, request);

            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
            assertEquals("An unexpected error occurred", response.getBody().get("message"));
        }
    }
}
