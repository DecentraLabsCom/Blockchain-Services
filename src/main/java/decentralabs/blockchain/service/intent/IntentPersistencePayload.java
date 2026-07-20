package decentralabs.blockchain.service.intent;

import com.fasterxml.jackson.annotation.JsonInclude;
import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;

/**
 * Durable intent material needed to resume on-chain execution.
 *
 * Federated assertions, WebAuthn assertions, and client signatures are
 * deliberately absent. They are request-time verification material and must
 * not become part of the intent retention boundary.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record IntentPersistencePayload(
    IntentMeta meta,
    ActionIntentPayload actionPayload,
    ReservationIntentPayload reservationPayload
) {

    public static IntentPersistencePayload from(IntentSubmission submission) {
        if (submission == null) {
            return new IntentPersistencePayload(null, null, null);
        }
        return new IntentPersistencePayload(
            submission.getMeta(),
            submission.getActionPayload(),
            submission.getReservationPayload()
        );
    }
}
