package decentralabs.blockchain.service.availability;

import java.math.BigInteger;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AvailabilityPolicyService {

    private static final LabAvailabilityRule GLOBAL_RULE = new LabAvailabilityRule(
        AvailabilityAction.AUTO_APPROVE,
        List.of("email", "calendar"),
        "Global auto workflow"
    );

    public AvailabilityPolicyService() {
        log.info("Availability policy initialized with mode {} and notifications {}", GLOBAL_RULE.action(), GLOBAL_RULE.notificationChannels());
    }

    public LabAvailabilityRule resolveRule(BigInteger labId) {
        return GLOBAL_RULE;
    }
}
