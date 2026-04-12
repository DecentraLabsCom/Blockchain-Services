package decentralabs.blockchain.dto.intent;

import decentralabs.blockchain.dto.identity.IdentityEvidenceDTO;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Request to initiate a WebAuthn authorization ceremony for an intent.
 * Mirrors IntentSubmission minus WebAuthn assertion fields.
 */
public class IntentAuthorizationRequest {

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
    // XXX: Legacy SAML assertion kept for backward compatibility during the transition.
    private String samlAssertion;

    @Valid
    private IdentityEvidenceDTO identityEvidence;

    private String returnUrl;

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

    public IdentityEvidenceDTO getIdentityEvidence() {
        return identityEvidence;
    }

    public void setIdentityEvidence(IdentityEvidenceDTO identityEvidence) {
        this.identityEvidence = identityEvidence;
    }

    public void setSamlAssertion(String samlAssertion) {
        this.samlAssertion = samlAssertion;
    }

    public String getReturnUrl() {
        return returnUrl;
    }

    public void setReturnUrl(String returnUrl) {
        this.returnUrl = returnUrl;
    }
}
