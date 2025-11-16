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
    
    /**
     * Constructor for authentication without booking info
     */
    public AuthResponse(String token) {
        this.token = token;
        this.labURL = null;
    }
    
    /**
     * Converts to JSON string format (maintaining backward compatibility)
     */
    public String toJson() {
        try {
            return OBJECT_MAPPER.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unable to serialize authentication response", e);
        }
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

