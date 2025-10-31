package decentralabs.blockchain.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Response DTO for authentication endpoints
 */
@Getter
@AllArgsConstructor
public class AuthResponse {
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
        if (labURL != null) {
            return "{\"token\": \"" + token + "\", \"labURL\": \"" + labURL + "\"}";
        }
        return "{\"token\": \"" + token + "\"}";
    }
    
    /**
     * Creates error response in JSON format
     */
    public static String errorJson(String message) {
        return "{\"error\": \"" + message + "\"}";
    }
}
