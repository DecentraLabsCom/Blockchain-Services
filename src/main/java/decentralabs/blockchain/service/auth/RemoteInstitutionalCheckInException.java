package decentralabs.blockchain.service.auth;

/** HTTP response received while delegating an institutional check-in. */
public class RemoteInstitutionalCheckInException extends RuntimeException {
    private final RemoteInstitutionalCheckInClient.RemoteCheckInResult result;

    public RemoteInstitutionalCheckInException(
        RemoteInstitutionalCheckInClient.RemoteCheckInResult result
    ) {
        super("Remote institutional check-in returned HTTP status "
            + (result == null ? "unknown" : result.status()));
        this.result = result;
    }

    public RemoteInstitutionalCheckInClient.RemoteCheckInResult result() {
        return result;
    }
}
