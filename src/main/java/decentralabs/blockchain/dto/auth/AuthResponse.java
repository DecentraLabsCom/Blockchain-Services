package decentralabs.blockchain.dto.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collections;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Response DTO for authentication endpoints
 */
@Getter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    
    private final String token;
    private final String labURL;
    private final String accessCode;
    private final String resourceType;
    private final String reservationKey;
    
    /**
     * Constructor for authentication without booking info
     */
    public AuthResponse(String token) {
        this(token, null, null, null, null);
    }

    public AuthResponse(String token, String labURL) {
        this(token, labURL, null, null, null);
    }

    public AuthResponse(String token, String labURL, String accessCode) {
        this(token, labURL, accessCode, null, null);
    }

    public AuthResponse(String token, String labURL, String accessCode, String resourceType) {
        this(token, labURL, accessCode, resourceType, null);
    }

    public static AuthResponse opaqueAccess(
        String accessCode, String labURL, String resourceType, String reservationKey
    ) {
        return new AuthResponse(null, labURL, accessCode, resourceType, reservationKey);
    }
    
    /**
     * Creates error response in JSON format
     */
    public static String errorJson(String message) {
        try {
            return OBJECT_MAPPER.writeValueAsString(Collections.singletonMap("error", message));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unable to serialize authentication error response", e);
        }
    }
}

