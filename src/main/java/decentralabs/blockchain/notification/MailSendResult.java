package decentralabs.blockchain.notification;

import java.util.Objects;

/**
 * Outcome of a notification delivery attempt.
 *
 * <p>A skipped notification is deliberately different from a sent one: a
 * caller such as the administrative test endpoint must not report success
 * when the selected driver did not actually submit a message.</p>
 */
public record MailSendResult(Status status, String message) {

    public enum Status {
        SENT,
        SKIPPED,
        FAILED
    }

    public MailSendResult {
        Objects.requireNonNull(status, "status");
    }

    public static MailSendResult sent() {
        return new MailSendResult(Status.SENT, null);
    }

    public static MailSendResult skipped(String message) {
        return new MailSendResult(Status.SKIPPED, message);
    }

    public static MailSendResult failed(String message) {
        return new MailSendResult(Status.FAILED, message);
    }
}
