package decentralabs.blockchain.service.availability;

import java.util.Collections;
import java.util.List;

public record LabAvailabilityRule(
    AvailabilityAction action,
    List<String> notificationChannels,
    String note
) {
    public static LabAvailabilityRule fallback() {
        return new LabAvailabilityRule(AvailabilityAction.MANUAL, Collections.emptyList(), null);
    }

    public LabAvailabilityRule {
        notificationChannels = notificationChannels == null
            ? Collections.emptyList()
            : List.copyOf(notificationChannels);
    }
}
