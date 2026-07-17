package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Atomically persists the opaque browser hand-off and its credential audit row. */
@Service
@RequiredArgsConstructor
public class AccessCredentialDeliveryService {
    private final AccessCodeService accessCodeService;
    private final AccessCredentialAuditService auditService;

    @Transactional
    public AuthResponse deliver(
        JwtService.IssuedToken issuedToken,
        Map<String, Object> marketplaceClaims,
        Map<String, Object> bookingInfo,
        AccessAuthorizationProvisioningService.ProvisioningLease lease
    ) {
        if (issuedToken == null || lease == null) {
            throw new IllegalArgumentException("Issued token and provisioning generation are required");
        }
        var accessCode = accessCodeService.issue(
            issuedToken.token(), lease.reservationKey(), lease.generation()
        );
        auditService.recordJwtIssuedRequired(marketplaceClaims, bookingInfo, issuedToken);
        return AuthResponse.opaqueAccess(
            accessCode.getAccessCode(),
            accessCode.getLabURL(),
            accessCode.getResourceType(),
            lease.reservationKey()
        );
    }
}
