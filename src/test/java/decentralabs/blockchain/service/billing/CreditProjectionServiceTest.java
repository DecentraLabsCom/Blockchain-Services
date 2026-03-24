package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.*;
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
@DisplayName("CreditProjectionService Tests")
class CreditProjectionServiceTest {

    @Mock
    private CreditAccountPersistenceService persistence;

    private CreditProjectionService service;

    private static final String ADDRESS = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    @BeforeEach
    void setUp() {
        service = new CreditProjectionService(persistence);
    }

    // ── syncAccount ─────────────────────────────────────────────────────

    @Nested
    @DisplayName("syncAccount")
    class SyncAccountTests {

        @Test
        @DisplayName("Upserts credit account with correct balances")
        void upsertsAccountWithBalances() {
            service.syncAccount(ADDRESS,
                    new BigDecimal("1000.00"),
                    new BigDecimal("200.00"),
                    new BigDecimal("500.00"),
                    BigDecimal.ZERO,
                    new BigDecimal("50.00"));

            ArgumentCaptor<CreditAccount> cap = ArgumentCaptor.forClass(CreditAccount.class);
            verify(persistence).upsertCreditAccount(cap.capture());
            CreditAccount account = cap.getValue();
            assertThat(account.getAccountAddress()).isEqualTo(ADDRESS.toLowerCase());
            assertThat(account.getAvailable()).isEqualByComparingTo("1000.00");
            assertThat(account.getLocked()).isEqualByComparingTo("200.00");
            assertThat(account.getConsumed()).isEqualByComparingTo("500.00");
            assertThat(account.getAdjusted()).isEqualByComparingTo("0.00");
            assertThat(account.getExpired()).isEqualByComparingTo("50.00");
        }

        @Test
        @DisplayName("Normalizes address to lowercase")
        void normalizesAddressToLowercase() {
            String mixedCase = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            service.syncAccount(mixedCase, BigDecimal.ONE, BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO);

            ArgumentCaptor<CreditAccount> cap = ArgumentCaptor.forClass(CreditAccount.class);
            verify(persistence).upsertCreditAccount(cap.capture());
            assertThat(cap.getValue().getAccountAddress()).isEqualTo(mixedCase.toLowerCase());
        }
    }

    // ── syncLot ─────────────────────────────────────────────────────────

    @Nested
    @DisplayName("syncLot — lot projection and expiry")
    class SyncLotTests {

        @Test
        @DisplayName("Syncs a non-expired lot with all fields")
        void syncsNonExpiredLot() {
            Instant issued = Instant.now().minusSeconds(86400);
            Instant expires = Instant.now().plusSeconds(86400 * 360L);

            service.syncLot(ADDRESS, 0, 42L, new BigDecimal("150.00"),
                    new BigDecimal("1500.0"), new BigDecimal("1200.0"),
                    issued, expires, false);

            ArgumentCaptor<CreditLot> cap = ArgumentCaptor.forClass(CreditLot.class);
            verify(persistence).upsertCreditLot(cap.capture());
            CreditLot lot = cap.getValue();
            assertThat(lot.getLotIndex()).isEqualTo(0);
            assertThat(lot.getFundingOrderId()).isEqualTo(42L);
            assertThat(lot.getEurGrossAmount()).isEqualByComparingTo("150.00");
            assertThat(lot.getCreditAmount()).isEqualByComparingTo("1500.0");
            assertThat(lot.getRemaining()).isEqualByComparingTo("1200.0");
            assertThat(lot.isExpired()).isFalse();
        }

        @Test
        @DisplayName("Syncs an expired lot and marks expired = true")
        void syncsExpiredLot() {
            Instant issued = Instant.now().minusSeconds(86400 * 400L);
            Instant expires = Instant.now().minusSeconds(86400 * 5L);

            service.syncLot(ADDRESS, 1, 43L, new BigDecimal("100.00"),
                    new BigDecimal("1000.0"), BigDecimal.ZERO,
                    issued, expires, true);

            ArgumentCaptor<CreditLot> cap = ArgumentCaptor.forClass(CreditLot.class);
            verify(persistence).upsertCreditLot(cap.capture());
            assertThat(cap.getValue().isExpired()).isTrue();
            assertThat(cap.getValue().getRemaining()).isEqualByComparingTo("0");
        }

        @Test
        @DisplayName("Syncs lot with null expiresAt (no-expiry lot)")
        void syncsLotWithNoExpiry() {
            service.syncLot(ADDRESS, 2, 44L, new BigDecimal("50.00"),
                    new BigDecimal("500.0"), new BigDecimal("500.0"),
                    Instant.now(), null, false);

            ArgumentCaptor<CreditLot> cap = ArgumentCaptor.forClass(CreditLot.class);
            verify(persistence).upsertCreditLot(cap.capture());
            assertThat(cap.getValue().getExpiresAt()).isNull();
        }
    }

    // ── recordMovement ───────────────────────────────────────────────────

    @Nested
    @DisplayName("recordMovement")
    class RecordMovementTests {

        @Test
        @DisplayName("Records a LOCK movement with reservation reference")
        void recordsLockMovement() {
            service.recordMovement(ADDRESS, 0, CreditMovement.Type.LOCK,
                    new BigDecimal("5000.00"), "RES-KEY-0001", null);

            ArgumentCaptor<CreditMovement> cap = ArgumentCaptor.forClass(CreditMovement.class);
            verify(persistence).recordMovement(cap.capture());
            CreditMovement m = cap.getValue();
            assertThat(m.getMovementType()).isEqualTo(CreditMovement.Type.LOCK);
            assertThat(m.getReservationRef()).isEqualTo("RES-KEY-0001");
        }

        @Test
        @DisplayName("Records a MINT movement with funding-order reference")
        void recordsMintMovement() {
            service.recordMovement(ADDRESS, null, CreditMovement.Type.MINT,
                    new BigDecimal("1500.0"), null, "funding-order:42");

            ArgumentCaptor<CreditMovement> cap = ArgumentCaptor.forClass(CreditMovement.class);
            verify(persistence).recordMovement(cap.capture());
            assertThat(cap.getValue().getReference()).isEqualTo("funding-order:42");
            assertThat(cap.getValue().getLotIndex()).isNull();
        }
    }
}
