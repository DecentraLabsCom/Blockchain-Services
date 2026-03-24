package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.ProviderNetworkMembership;
import decentralabs.blockchain.service.persistence.ProviderNetworkPersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

/**
 * Manages the limited-network provider registry — membership activation,
 * suspension, termination, and contract expiry queries.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ProviderNetworkService {

    private final ProviderNetworkPersistenceService persistence;

    @Transactional
    public ProviderNetworkMembership activate(String providerAddress, String contractId,
                                               String agreementVersion,
                                               LocalDate effectiveDate, LocalDate expiryDate,
                                               String activatedBy) {
        if (providerAddress == null || providerAddress.isBlank()) {
            throw new IllegalArgumentException("Provider address required");
        }
        if (contractId == null || contractId.isBlank()) {
            throw new IllegalArgumentException("Contract ID required");
        }
        if (agreementVersion == null || agreementVersion.isBlank()) {
            throw new IllegalArgumentException("Agreement version required — provider cannot be activated without a signed merchant agreement version on file");
        }

        ProviderNetworkMembership membership = ProviderNetworkMembership.builder()
                .providerAddress(providerAddress.toLowerCase())
                .contractId(contractId.trim())
                .agreementVersion(agreementVersion.trim())
                .effectiveDate(effectiveDate != null ? effectiveDate : LocalDate.now())
                .expiryDate(expiryDate)
                .status(ProviderNetworkMembership.Status.ACTIVE)
                .actionBy(activatedBy)
                .build();

        membership = persistence.createMembership(membership);
        log.info("Activated provider {} in network (contract {}, agreement {}), by {}",
                providerAddress, contractId, agreementVersion, activatedBy);
        return membership;
    }

    @Transactional
    public void suspend(long membershipId, String reason, String actionBy) {
        persistence.updateMembershipStatus(membershipId, ProviderNetworkMembership.Status.SUSPENDED, reason, actionBy);
        log.info("Suspended provider membership {} by {}: {}", membershipId, actionBy, reason);
    }

    @Transactional
    public void terminate(long membershipId, String actionBy) {
        persistence.updateMembershipStatus(membershipId, ProviderNetworkMembership.Status.TERMINATED, null, actionBy);
        log.info("Terminated provider membership {} by {}", membershipId, actionBy);
    }

    public Optional<ProviderNetworkMembership> findByProvider(String providerAddress) {
        return persistence.findByProvider(providerAddress.toLowerCase());
    }

    public List<ProviderNetworkMembership> findAllActive() {
        return persistence.findAllActive();
    }

    public List<ProviderNetworkMembership> findAll() {
        return persistence.findAll();
    }

    public List<ProviderNetworkMembership> findExpiringBefore(LocalDate date) {
        return persistence.findExpiringBefore(date);
    }

    /**
     * Check if a provider has an active network membership.
     */
    public boolean isProviderInNetwork(String providerAddress) {
        return persistence.findByProvider(providerAddress.toLowerCase()).isPresent();
    }
}
