package decentralabs.blockchain.dto.auth;

import java.util.Map;

public class FmuSessionTicketRedeemResponse {
    private Map<String, Object> claims;
    private long expiresAt;
    private String sessionId;
    private boolean sessionObserved;
    private boolean auditRecorded;
    private boolean attestationRecorded;

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

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public boolean isSessionObserved() {
        return sessionObserved;
    }

    public void setSessionObserved(boolean sessionObserved) {
        this.sessionObserved = sessionObserved;
    }

    public boolean isAuditRecorded() {
        return auditRecorded;
    }

    public void setAuditRecorded(boolean auditRecorded) {
        this.auditRecorded = auditRecorded;
    }

    public boolean isAttestationRecorded() {
        return attestationRecorded;
    }

    public void setAttestationRecorded(boolean attestationRecorded) {
        this.attestationRecorded = attestationRecorded;
    }
}
