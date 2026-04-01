package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.CreditLot;
import decentralabs.blockchain.service.persistence.CreditAccountPersistenceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CreditExpiryScheduler Tests — lot expiry processing")
class CreditExpirySchedulerTest {

    @Mock
    private CreditAccountPersistenceService creditPersistence;

    private CreditExpiryScheduler scheduler;

    @BeforeEach
    void setUp() {
        scheduler = new CreditExpiryScheduler(creditPersistence);
    }

    @Nested
    @DisplayName("processExpiringLots")
    class ProcessExpiringLotsTests {

        @Test
        @DisplayName("No-op when no lots are expiring")
        void noOpWhenNoLotsExpiring() {
            when(creditPersistence.findExpiringLots(any())).thenReturn(List.of());

            scheduler.processExpiringLots();

            verify(creditPersistence).findExpiringLots(any());
            verify(creditPersistence, never()).upsertCreditLot(any());
        }

        @Test
        @DisplayName("Marks a single expiring lot as expired")
        void marksExpiringLotAsExpired() {
            CreditLot lot = buildLot("0xaabbccddaabbccddaabbccddaabbccddaabbccdd", 0, false);
            when(creditPersistence.findExpiringLots(any())).thenReturn(List.of(lot));

            scheduler.processExpiringLots();

            ArgumentCaptor<CreditLot> cap = ArgumentCaptor.forClass(CreditLot.class);
            verify(creditPersistence).upsertCreditLot(cap.capture());
            assertThat(cap.getValue().isExpired()).isTrue();
        }

        @Test
        @DisplayName("Marks all expiring lots when multiple lots expire")
        void marksAllExpiringLots() {
            String addr1 = "0x1111111111111111111111111111111111111111";
            String addr2 = "0x2222222222222222222222222222222222222222";
            CreditLot lot1 = buildLot(addr1, 0, false);
            CreditLot lot2 = buildLot(addr2, 1, false);
            when(creditPersistence.findExpiringLots(any())).thenReturn(List.of(lot1, lot2));

            scheduler.processExpiringLots();

            verify(creditPersistence, times(2)).upsertCreditLot(any());
        }

        @Test
        @DisplayName("Continues processing remaining lots when one lot fails to expire")
        void continuesOnPartialFailure() {
            CreditLot lot1 = buildLot("0x1111111111111111111111111111111111111111", 0, false);
            CreditLot lot2 = buildLot("0x2222222222222222222222222222222222222222", 1, false);
            when(creditPersistence.findExpiringLots(any())).thenReturn(List.of(lot1, lot2));
            // First lot fails
            doThrow(new RuntimeException("DB error"))
                    .doNothing()
                    .when(creditPersistence).upsertCreditLot(any());

            // Should not throw
            scheduler.processExpiringLots();

            // Both are attempted
            verify(creditPersistence, times(2)).upsertCreditLot(any());
        }

        @Test
        @DisplayName("Handles persistence exception in findExpiringLots gracefully")
        void handlesFindExpiringLotsException() {
            when(creditPersistence.findExpiringLots(any()))
                    .thenThrow(new RuntimeException("DB unavailable"));

            // Must not propagate
            scheduler.processExpiringLots();

            verify(creditPersistence, never()).upsertCreditLot(any());
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private CreditLot buildLot(String address, int index, boolean expired) {
        return CreditLot.builder()
                .accountAddress(address.toLowerCase())
                .lotIndex(index)
                .fundingOrderId(100L + index)
                .eurGrossAmount(new BigDecimal("100.00"))
                .creditAmount(new BigDecimal("100000000.00000"))
                .remaining(expired ? BigDecimal.ZERO : new BigDecimal("100000000.00000"))
                .issuedAt(Instant.now().minusSeconds(86400 * 400L))
                .expiresAt(Instant.now().minusSeconds(86400))
                .expired(expired)
                .build();
    }
}
