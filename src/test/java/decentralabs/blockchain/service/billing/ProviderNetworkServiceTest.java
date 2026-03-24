package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.ProviderNetworkMembership;
import decentralabs.blockchain.service.persistence.ProviderNetworkPersistenceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDate;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ProviderNetworkService Tests — activation gating and audit trail")
class ProviderNetworkServiceTest {

    @Mock
    private ProviderNetworkPersistenceService persistence;

    private ProviderNetworkService service;

    private static final String PROVIDER = "0x1234567890abcdef1234567890abcdef12345678";
    private static final String CONTRACT_ID = "CONTRACT-2025-001";
    private static final String AGREEMENT_VERSION = "v2.1";
    private static final String ACTIVATED_BY = "0xadminadminadminadminadminadminadminadmin";

    @BeforeEach
    void setUp() {
        service = new ProviderNetworkService(persistence);
    }

    // ── activate ────────────────────────────────────────────────────────

    @Nested
    @DisplayName("activate — provider network activation gating")
    class ActivateTests {

        @Test
        @DisplayName("Activates provider with all required fields")
        void activatesProviderSuccessfully() {
            ProviderNetworkMembership saved = buildMembership(1L, ProviderNetworkMembership.Status.ACTIVE);
            when(persistence.createMembership(any())).thenReturn(saved);

            ProviderNetworkMembership result = service.activate(PROVIDER, CONTRACT_ID, AGREEMENT_VERSION,
                    LocalDate.now(), LocalDate.now().plusYears(1), ACTIVATED_BY);

            assertThat(result.getStatus()).isEqualTo(ProviderNetworkMembership.Status.ACTIVE);
            ArgumentCaptor<ProviderNetworkMembership> cap = ArgumentCaptor.forClass(ProviderNetworkMembership.class);
            verify(persistence).createMembership(cap.capture());
            ProviderNetworkMembership built = cap.getValue();
            assertThat(built.getProviderAddress()).isEqualTo(PROVIDER.toLowerCase());
            assertThat(built.getAgreementVersion()).isEqualTo(AGREEMENT_VERSION);
            assertThat(built.getActionBy()).isEqualTo(ACTIVATED_BY);
        }

        @Test
        @DisplayName("Rejects activation without agreement version")
        void rejectsActivationWithoutAgreementVersion() {
            assertThatThrownBy(() ->
                    service.activate(PROVIDER, CONTRACT_ID, null,
                            LocalDate.now(), null, ACTIVATED_BY))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agreement version required");
        }

        @Test
        @DisplayName("Rejects activation with blank agreement version")
        void rejectsActivationWithBlankAgreementVersion() {
            assertThatThrownBy(() ->
                    service.activate(PROVIDER, CONTRACT_ID, "   ",
                            LocalDate.now(), null, ACTIVATED_BY))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agreement version required");
        }

        @Test
        @DisplayName("Rejects activation with blank contract ID")
        void rejectsActivationWithBlankContractId() {
            assertThatThrownBy(() ->
                    service.activate(PROVIDER, "  ", AGREEMENT_VERSION,
                            LocalDate.now(), null, ACTIVATED_BY))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Contract ID");
        }

        @Test
        @DisplayName("Rejects activation with blank provider address")
        void rejectsActivationWithBlankProviderAddress() {
            assertThatThrownBy(() ->
                    service.activate("", CONTRACT_ID, AGREEMENT_VERSION,
                            LocalDate.now(), null, ACTIVATED_BY))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Provider address");
        }

        @Test
        @DisplayName("Uses today as effective date when null is passed")
        void usesTodayAsDefaultEffectiveDate() {
            ProviderNetworkMembership saved = buildMembership(1L, ProviderNetworkMembership.Status.ACTIVE);
            when(persistence.createMembership(any())).thenReturn(saved);

            service.activate(PROVIDER, CONTRACT_ID, AGREEMENT_VERSION, null, null, ACTIVATED_BY);

            ArgumentCaptor<ProviderNetworkMembership> cap = ArgumentCaptor.forClass(ProviderNetworkMembership.class);
            verify(persistence).createMembership(cap.capture());
            assertThat(cap.getValue().getEffectiveDate()).isEqualTo(LocalDate.now());
        }
    }

    // ── suspend ──────────────────────────────────────────────────────────

    @Nested
    @DisplayName("suspend — audit trail")
    class SuspendTests {

        @Test
        @DisplayName("Suspends membership with reason and actionBy")
        void suspendsMembershipWithAuditTrail() {
            service.suspend(42L, "Contract expired", "ops@decentralabs.eu");

            verify(persistence).updateMembershipStatus(42L,
                    ProviderNetworkMembership.Status.SUSPENDED,
                    "Contract expired",
                    "ops@decentralabs.eu");
        }

        @Test
        @DisplayName("Suspends with null actionBy (legacy path)")
        void suspendsWithNullActionBy() {
            service.suspend(5L, "Investigation", null);

            verify(persistence).updateMembershipStatus(5L,
                    ProviderNetworkMembership.Status.SUSPENDED,
                    "Investigation",
                    null);
        }
    }

    // ── terminate ────────────────────────────────────────────────────────

    @Nested
    @DisplayName("terminate — audit trail")
    class TerminateTests {

        @Test
        @DisplayName("Terminates membership with actionBy")
        void terminatesMembership() {
            service.terminate(7L, "admin-ops");

            verify(persistence).updateMembershipStatus(7L,
                    ProviderNetworkMembership.Status.TERMINATED,
                    null,
                    "admin-ops");
        }
    }

    // ── isProviderInNetwork ──────────────────────────────────────────────

    @Nested
    @DisplayName("isProviderInNetwork")
    class IsProviderInNetworkTests {

        @Test
        @DisplayName("Returns true when active membership exists")
        void returnsTrueForActiveMembership() {
            when(persistence.findByProvider(PROVIDER.toLowerCase()))
                    .thenReturn(Optional.of(buildMembership(1L, ProviderNetworkMembership.Status.ACTIVE)));

            assertThat(service.isProviderInNetwork(PROVIDER)).isTrue();
        }

        @Test
        @DisplayName("Returns false when no active membership")
        void returnsFalseWhenNoMembership() {
            when(persistence.findByProvider(PROVIDER.toLowerCase())).thenReturn(Optional.empty());

            assertThat(service.isProviderInNetwork(PROVIDER)).isFalse();
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private ProviderNetworkMembership buildMembership(long id, ProviderNetworkMembership.Status status) {
        return ProviderNetworkMembership.builder()
                .id(id)
                .providerAddress(PROVIDER.toLowerCase())
                .contractId(CONTRACT_ID)
                .agreementVersion(AGREEMENT_VERSION)
                .effectiveDate(LocalDate.now())
                .status(status)
                .actionBy(ACTIVATED_BY)
                .build();
    }
}
