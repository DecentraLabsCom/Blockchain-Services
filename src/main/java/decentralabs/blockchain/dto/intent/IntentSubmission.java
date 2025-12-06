package decentralabs.blockchain.dto.intent;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IntentSubmission {

    @Valid
    @NotNull
    private IntentMeta meta;

    @Valid
    private ActionIntentPayload actionPayload;

    @Valid
    private ReservationIntentPayload reservationPayload;

    @NotBlank
    private String signature;

    @NotBlank
    private String samlAssertion;

    @NotBlank
    private String webauthnCredentialId; // Credential used for WebAuthn assertion

    @NotBlank
    private String webauthnClientDataJSON; // base64url

    @NotBlank
    private String webauthnAuthenticatorData; // base64url

    @NotBlank
    private String webauthnSignature; // base64url ECDSA signature

    private Map<String, Object> typedData;

    public IntentMeta getMeta() {
        return meta;
    }

    public void setMeta(IntentMeta meta) {
        this.meta = meta;
    }

    public ActionIntentPayload getActionPayload() {
        return actionPayload;
    }

    public void setActionPayload(ActionIntentPayload actionPayload) {
        this.actionPayload = actionPayload;
    }

    public ReservationIntentPayload getReservationPayload() {
        return reservationPayload;
    }

    public void setReservationPayload(ReservationIntentPayload reservationPayload) {
        this.reservationPayload = reservationPayload;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getSamlAssertion() {
        return samlAssertion;
    }

    public void setSamlAssertion(String samlAssertion) {
        this.samlAssertion = samlAssertion;
    }

    public String getWebauthnCredentialId() {
        return webauthnCredentialId;
    }

    public void setWebauthnCredentialId(String webauthnCredentialId) {
        this.webauthnCredentialId = webauthnCredentialId;
    }

    public String getWebauthnClientDataJSON() {
        return webauthnClientDataJSON;
    }

    public void setWebauthnClientDataJSON(String webauthnClientDataJSON) {
        this.webauthnClientDataJSON = webauthnClientDataJSON;
    }

    public String getWebauthnAuthenticatorData() {
        return webauthnAuthenticatorData;
    }

    public void setWebauthnAuthenticatorData(String webauthnAuthenticatorData) {
        this.webauthnAuthenticatorData = webauthnAuthenticatorData;
    }

    public String getWebauthnSignature() {
        return webauthnSignature;
    }

    public void setWebauthnSignature(String webauthnSignature) {
        this.webauthnSignature = webauthnSignature;
    }

    public Map<String, Object> getTypedData() {
        return typedData;
    }

    public void setTypedData(Map<String, Object> typedData) {
        this.typedData = typedData;
    }
}
