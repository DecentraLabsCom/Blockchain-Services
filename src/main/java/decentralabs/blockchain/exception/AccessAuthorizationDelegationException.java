package decentralabs.blockchain.exception;

import decentralabs.blockchain.service.auth.RemoteInstitutionalCheckInClient;

/** A remote institutional check-in response that must be preserved by the fast path. */
public class AccessAuthorizationDelegationException extends RuntimeException {
    private final RemoteInstitutionalCheckInClient.RemoteCheckInResult result;

    public AccessAuthorizationDelegationException(
        RemoteInstitutionalCheckInClient.RemoteCheckInResult result
    ) {
        super(messageFor(result));
        this.result = result;
    }

    public RemoteInstitutionalCheckInClient.RemoteCheckInResult result() {
        return result;
    }

    private static String messageFor(RemoteInstitutionalCheckInClient.RemoteCheckInResult result) {
        if (result != null && result.body() != null && result.body().getReason() != null) {
            return result.body().getReason();
        }
        return "Remote institutional check-in failed";
    }
}
