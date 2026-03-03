package decentralabs.blockchain.dto.auth;

import java.util.Map;

public class FmuSessionTicketRedeemResponse {
    private Map<String, Object> claims;
    private long expiresAt;

    public Map<String, Object> getClaims() {
        return claims;
    }

    public void setClaims(Map<String, Object> claims) {
        this.claims = claims;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
    }
}
