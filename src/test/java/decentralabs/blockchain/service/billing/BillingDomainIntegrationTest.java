package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.*;
import decentralabs.blockchain.service.persistence.CreditAccountPersistenceService;
import decentralabs.blockchain.service.persistence.FundingOrderPersistenceService;
import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * Integration tests for the billing domain against an in-memory H2 database.
 *
 * Verifies end-to-end behaviour of the service layer against real SQL without
 * requiring a live MySQL instance or the full Spring application context.
 *
 * Uses a minimal Spring context (no Boot auto-configuration) because
 * {@code @JdbcTest} was removed in Spring Boot 4.0.
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = BillingDomainIntegrationTest.TestConfig.class)
@Sql("/integration/billing-schema.sql")
@DisplayName("Billing domain – integration tests")
class BillingDomainIntegrationTest {

    @Configuration
    static class TestConfig {

        @Bean
        DataSource dataSource() {
            SimpleDriverDataSource ds = new SimpleDriverDataSource();
            ds.setDriverClass(org.h2.Driver.class);
            ds.setUrl("jdbc:h2:mem:billing-test;DB_CLOSE_DELAY=-1;MODE=MySQL");
            return ds;
        }

        @Bean
        JdbcTemplate jdbcTemplate(DataSource dataSource) {
            return new JdbcTemplate(dataSource);
        }

        @Bean
        PlatformTransactionManager transactionManager(DataSource dataSource) {
            return new DataSourceTransactionManager(dataSource);
        }

        @Bean
        FundingOrderPersistenceService fundingOrderPersistenceService(JdbcTemplate jt) {
            return new FundingOrderPersistenceService(objectProviderOf(jt));
        }

        @Bean
        CreditAccountPersistenceService creditAccountPersistenceService(JdbcTemplate jt) {
            return new CreditAccountPersistenceService(objectProviderOf(jt));
        }

        @Bean
        FundingOrderService fundingOrderService(FundingOrderPersistenceService fop,
                                                CreditAccountPersistenceService cap) {
            return new FundingOrderService(fop, cap);
        }

        @Bean
        ProviderSettlementPersistenceService providerSettlementPersistenceService(JdbcTemplate jt) {
            return new ProviderSettlementPersistenceService(objectProviderOf(jt));
        }

        @Bean
        ProviderSettlementService providerSettlementService(ProviderSettlementPersistenceService psp) {
            return new ProviderSettlementService(psp);
        }

        @Bean
        CreditProjectionService creditProjectionService(CreditAccountPersistenceService cap) {
            return new CreditProjectionService(cap);
        }

        private static <T> ObjectProvider<T> objectProviderOf(T instance) {
            return new ObjectProvider<>() {
                @Override public T getObject() { return instance; }
                @Override public T getObject(Object... args) { return instance; }
                @Override public T getIfAvailable() { return instance; }
                @Override public T getIfUnique() { return instance; }
            };
        }
    }

    @Autowired
    FundingOrderService fundingOrderService;

    @Autowired
    ProviderSettlementService providerSettlementService;

    @Autowired
    CreditProjectionService creditProjectionService;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanTables() {
        // Truncate in reverse FK order
        jdbcTemplate.execute("DELETE FROM provider_approvals");
        jdbcTemplate.execute("DELETE FROM provider_invoice_records");
        jdbcTemplate.execute("DELETE FROM provider_payouts");
        jdbcTemplate.execute("DELETE FROM payment_reconciliations");
        jdbcTemplate.execute("DELETE FROM funding_invoices");
        jdbcTemplate.execute("DELETE FROM credit_movements");
        jdbcTemplate.execute("DELETE FROM credit_lots");
        jdbcTemplate.execute("DELETE FROM credit_accounts");
        jdbcTemplate.execute("DELETE FROM funding_orders");
    }

    // ── Funding order lifecycle ─────────────────────────────────────────

    @Test
    @DisplayName("full funding order lifecycle: create → invoice → confirm payment → cancel blocked after credit")
    void fundingOrderLifecycle() {
        FundingOrder order = fundingOrderService.createFundingOrder(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001",
                new BigDecimal("500.00"), new BigDecimal("5000.00"),
                "REF-001", null);

        assertThat(order.getId()).isNotNull();
        assertThat(order.getStatus()).isEqualTo(FundingOrder.Status.DRAFT);

        FundingInvoice invoice = fundingOrderService.issueInvoice(order.getId(), "INV-2026-001", null);
        assertThat(invoice.getInvoiceNumber()).isEqualTo("INV-2026-001");

        assertThatThrownBy(() -> fundingOrderService.issueInvoice(order.getId(), "INV-DUPE", null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("DRAFT");

        PaymentReconciliation recon = fundingOrderService.confirmPayment(
                order.getId(), "BANK-REF-00001", new BigDecimal("500.00"), "SEPA");
        assertThat(recon.getPaymentRef()).isEqualTo("BANK-REF-00001");

        fundingOrderService.markCredited(order.getId());

        assertThatThrownBy(() -> fundingOrderService.cancelFundingOrder(order.getId()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("CREDITED");
    }

    @Test
    @DisplayName("payment reconciliation idempotency: second confirm on PAID order throws")
    void paymentReconciliationIdempotency() {
        FundingOrder order = fundingOrderService.createFundingOrder(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0002",
                new BigDecimal("100.00"), new BigDecimal("1000.00"), null, null);
        fundingOrderService.issueInvoice(order.getId(), "INV-IDEM-001", null);
        fundingOrderService.confirmPayment(order.getId(), "BANK-IDEM-001", new BigDecimal("100.00"), "SEPA");

        assertThatThrownBy(() ->
                fundingOrderService.confirmPayment(order.getId(), "BANK-IDEM-002", new BigDecimal("100.00"), "SEPA"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("INVOICED");
    }

    @Test
    @DisplayName("cancel funding order while still DRAFT succeeds")
    void cancelDraftOrder() {
        FundingOrder order = fundingOrderService.createFundingOrder(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0003",
                new BigDecimal("250.00"), new BigDecimal("2500.00"), "CANCEL-ME", null);

        fundingOrderService.cancelFundingOrder(order.getId());

        FundingOrder loaded = fundingOrderService.findById(order.getId()).orElseThrow();
        assertThat(loaded.getStatus()).isEqualTo(FundingOrder.Status.CANCELLED);
    }

    // ── Provider settlement lifecycle ───────────────────────────────────

    @Test
    @DisplayName("provider settlement lifecycle: submit invoice → approve with ref → mark paid")
    void providerSettlementLifecycle() {
        ProviderInvoiceRecord record = providerSettlementService.submitInvoice(
                "1",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0001",
                "PINV-2026-001",
                new BigDecimal("800.00"),
                new BigDecimal("8000.00"));

        assertThat(record.getId()).isNotNull();
        assertThat(record.getStatus()).isEqualTo(ProviderInvoiceRecord.Status.SUBMITTED);

        ProviderApproval approval = providerSettlementService.approveInvoice(
                record.getId(),
                "0xcccccccccccccccccccccccccccccccccccc0001",
                "APPROVAL-2026-0042",
                new BigDecimal("800.00"));

        assertThat(approval.getApprovalRef()).isEqualTo("APPROVAL-2026-0042");
        assertThat(approval.getApprovedBy()).isEqualTo("0xcccccccccccccccccccccccccccccccccccc0001");

        ProviderInvoiceRecord reloaded = providerSettlementService
                .findInvoicesByProvider("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0001")
                .stream().findFirst().orElseThrow();
        assertThat(reloaded.getStatus()).isEqualTo(ProviderInvoiceRecord.Status.APPROVED);
    }

    @Test
    @DisplayName("approvalRef is persisted and round-trips correctly")
    void approvalRefPersistedAndRoundTrips() {
        ProviderInvoiceRecord record = providerSettlementService.submitInvoice(
                "2",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0002",
                "PINV-REF-TEST",
                new BigDecimal("200.00"),
                null);

        ProviderApproval approval = providerSettlementService.approveInvoice(
                record.getId(),
                "0xcccccccccccccccccccccccccccccccccccc0002",
                "APPR-XYZ-9999",
                new BigDecimal("200.00"));

        assertThat(approval.getApprovalRef()).isEqualTo("APPR-XYZ-9999");
    }

    @Test
    @DisplayName("null approvalRef is accepted (optional field)")
    void approvalRefOptional() {
        ProviderInvoiceRecord record = providerSettlementService.submitInvoice(
                "3",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0003",
                "PINV-NO-REF",
                new BigDecimal("50.00"),
                null);

        ProviderApproval approval = providerSettlementService.approveInvoice(
                record.getId(),
                "0xcccccccccccccccccccccccccccccccccccc0003",
                null,
                new BigDecimal("50.00"));

        assertThat(approval.getApprovalRef()).isNull();
    }

    @Test
    @DisplayName("approving a non-SUBMITTED invoice throws IllegalStateException")
    void approveNonSubmittedThrows() {
        ProviderInvoiceRecord record = providerSettlementService.submitInvoice(
                "4",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0004",
                "PINV-DOUBLE-APPROVE",
                new BigDecimal("100.00"),
                null);

        providerSettlementService.approveInvoice(
                record.getId(),
                "0xcccccccccccccccccccccccccccccccccccc0004",
                "APPR-001",
                new BigDecimal("100.00"));

        assertThatThrownBy(() -> providerSettlementService.approveInvoice(
                record.getId(),
                "0xcccccccccccccccccccccccccccccccccccc0004",
                "APPR-002",
                new BigDecimal("100.00")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SUBMITTED");
    }

    // ── End-to-end validation ───────────────────────────────

    @Nested
    @DisplayName("E2E – canonical billing lifecycle")
    class CanonicalLifecycleTests {

        private static final String INSTITUTION = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1001";
        private static final String PROVIDER    = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1001";
        private static final String ADMIN       = "0xcccccccccccccccccccccccccccccccccccc1001";

        @Test
        @DisplayName("full canonical flow: fund → mint → lock → capture → accrue → approve → payout")
        void fullCanonicalFlow() {
            // 1. Create funding order (EUR 100 → 1000 credits)
            FundingOrder order = fundingOrderService.createFundingOrder(
                    INSTITUTION, new BigDecimal("100.00"), new BigDecimal("1000.0"), "E2E-REF", null);
            assertThat(order.getStatus()).isEqualTo(FundingOrder.Status.DRAFT);

            // 2. Issue invoice
            FundingInvoice invoice = fundingOrderService.issueInvoice(order.getId(), "INV-E2E-001", null);
            assertThat(invoice.getInvoiceNumber()).isEqualTo("INV-E2E-001");

            // 3. Confirm EUR payment
            PaymentReconciliation recon = fundingOrderService.confirmPayment(
                    order.getId(), "SEPA-E2E-001", new BigDecimal("100.00"), "SEPA");
            assertThat(recon.getPaymentRef()).isEqualTo("SEPA-E2E-001");

            // MINT movement recorded automatically by confirmPayment
            List<CreditMovement> movements = creditProjectionService.getMovements(INSTITUTION, 10);
            assertThat(movements).hasSize(1);
            assertThat(movements.getFirst().getMovementType()).isEqualTo(CreditMovement.Type.MINT);
            assertThat(movements.getFirst().getAmount()).isEqualByComparingTo("1000.0");

            // 4. Mint service credits — sync the credit account and lot projections
            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("1000.0"), BigDecimal.ZERO, BigDecimal.ZERO,
                    BigDecimal.ZERO, BigDecimal.ZERO);
            creditProjectionService.syncLot(INSTITUTION, 0, order.getId(),
                    new BigDecimal("100.00"), new BigDecimal("1000.0"), new BigDecimal("1000.0"),
                    Instant.now(), Instant.now().plus(365, ChronoUnit.DAYS), false);

            // Mark funding order as credited
            fundingOrderService.markCredited(order.getId());
            FundingOrder credited = fundingOrderService.findById(order.getId()).orElseThrow();
            assertThat(credited.getStatus()).isEqualTo(FundingOrder.Status.CREDITED);

            // Verify credit account snapshot
            CreditAccount account = creditProjectionService.getAccount(INSTITUTION).orElseThrow();
            assertThat(account.getAvailable()).isEqualByComparingTo("1000.0");
            assertThat(account.getLocked()).isEqualByComparingTo("0");

            // 5. Make reservation — lock credits
            creditProjectionService.recordMovement(INSTITUTION, 0, CreditMovement.Type.LOCK,
                    new BigDecimal("200.0"), "reservation:RES-001", "lab:LAB-001");
            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("800.0"), new BigDecimal("200.0"), BigDecimal.ZERO,
                    BigDecimal.ZERO, BigDecimal.ZERO);

            CreditAccount afterLock = creditProjectionService.getAccount(INSTITUTION).orElseThrow();
            assertThat(afterLock.getAvailable()).isEqualByComparingTo("800.0");
            assertThat(afterLock.getLocked()).isEqualByComparingTo("200.0");

            // 6. Execute service + capture credits
            creditProjectionService.recordMovement(INSTITUTION, 0, CreditMovement.Type.CAPTURE,
                    new BigDecimal("200.0"), "reservation:RES-001", "lab:LAB-001");
            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("800.0"), BigDecimal.ZERO, new BigDecimal("200.0"),
                    BigDecimal.ZERO, BigDecimal.ZERO);

            CreditAccount afterCapture = creditProjectionService.getAccount(INSTITUTION).orElseThrow();
            assertThat(afterCapture.getAvailable()).isEqualByComparingTo("800.0");
            assertThat(afterCapture.getLocked()).isEqualByComparingTo("0");
            assertThat(afterCapture.getConsumed()).isEqualByComparingTo("200.0");

            // 7. Accrue provider receivable — submit invoice
            ProviderInvoiceRecord provInvoice = providerSettlementService.submitInvoice(
                    "LAB-001", PROVIDER, "PINV-E2E-001",
                    new BigDecimal("20.00"), new BigDecimal("200.0"));
            assertThat(provInvoice.getStatus()).isEqualTo(ProviderInvoiceRecord.Status.SUBMITTED);

            // 8. Approve payout
            ProviderApproval approval = providerSettlementService.approveInvoice(
                    provInvoice.getId(), ADMIN, "APPR-E2E-001", new BigDecimal("20.00"));
            assertThat(approval.getApprovalRef()).isEqualTo("APPR-E2E-001");

            // 9. Execute payout
            providerSettlementService.recordPayout(
                    "LAB-001", PROVIDER, new BigDecimal("20.00"), new BigDecimal("200.0"),
                    "BANK-E2E-001", null, null);

            // Verify full audit trail — 3 movements: MINT, LOCK, CAPTURE
            List<CreditMovement> allMovements = creditProjectionService.getMovements(INSTITUTION, 20);
            assertThat(allMovements).hasSize(3);
            assertThat(allMovements).extracting(CreditMovement::getMovementType)
                    .containsExactly(CreditMovement.Type.CAPTURE, CreditMovement.Type.LOCK, CreditMovement.Type.MINT);

            // Verify credit lot remaining
            List<CreditLot> lots = creditProjectionService.getLots(INSTITUTION);
            assertThat(lots).hasSize(1);
            assertThat(lots.getFirst().getRemaining()).isEqualByComparingTo("1000.0");
        }

        @Test
        @DisplayName("cancellation and release before capture")
        void cancellationAndReleaseBeforeCapture() {
            // Fund the account
            FundingOrder order = fundingOrderService.createFundingOrder(
                    INSTITUTION, new BigDecimal("50.00"), new BigDecimal("500.0"), null, null);
            fundingOrderService.issueInvoice(order.getId(), "INV-CANCEL-001", null);
            fundingOrderService.confirmPayment(order.getId(), "SEPA-CANCEL-001", new BigDecimal("50.00"), "SEPA");
            fundingOrderService.markCredited(order.getId());

            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("500.0"), BigDecimal.ZERO, BigDecimal.ZERO,
                    BigDecimal.ZERO, BigDecimal.ZERO);

            // Lock credits for reservation
            creditProjectionService.recordMovement(INSTITUTION, 0, CreditMovement.Type.LOCK,
                    new BigDecimal("300.0"), "reservation:RES-CANCEL", "lab:LAB-002");
            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("200.0"), new BigDecimal("300.0"), BigDecimal.ZERO,
                    BigDecimal.ZERO, BigDecimal.ZERO);

            CreditAccount afterLock = creditProjectionService.getAccount(INSTITUTION).orElseThrow();
            assertThat(afterLock.getAvailable()).isEqualByComparingTo("200.0");
            assertThat(afterLock.getLocked()).isEqualByComparingTo("300.0");

            // Cancel reservation → release locked credits (CANCEL movement)
            creditProjectionService.recordMovement(INSTITUTION, 0, CreditMovement.Type.CANCEL,
                    new BigDecimal("300.0"), "reservation:RES-CANCEL", "lab:LAB-002");
            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("500.0"), BigDecimal.ZERO, BigDecimal.ZERO,
                    BigDecimal.ZERO, BigDecimal.ZERO);

            CreditAccount afterCancel = creditProjectionService.getAccount(INSTITUTION).orElseThrow();
            assertThat(afterCancel.getAvailable()).isEqualByComparingTo("500.0");
            assertThat(afterCancel.getLocked()).isEqualByComparingTo("0");
            assertThat(afterCancel.getConsumed()).isEqualByComparingTo("0");

            // Verify movement trail: MINT, LOCK, CANCEL (reverse chrono)
            List<CreditMovement> movements = creditProjectionService.getMovements(INSTITUTION, 20);
            assertThat(movements).hasSize(3);
            assertThat(movements).extracting(CreditMovement::getMovementType)
                    .containsExactly(CreditMovement.Type.CANCEL, CreditMovement.Type.LOCK, CreditMovement.Type.MINT);
        }

        @Test
        @DisplayName("post-capture adjustment")
        void postCaptureAdjustment() {
            // Fund and consume
            FundingOrder order = fundingOrderService.createFundingOrder(
                    INSTITUTION, new BigDecimal("80.00"), new BigDecimal("800.0"), null, null);
            fundingOrderService.issueInvoice(order.getId(), "INV-ADJUST-001", null);
            fundingOrderService.confirmPayment(order.getId(), "SEPA-ADJUST-001", new BigDecimal("80.00"), "SEPA");
            fundingOrderService.markCredited(order.getId());

            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("800.0"), BigDecimal.ZERO, BigDecimal.ZERO,
                    BigDecimal.ZERO, BigDecimal.ZERO);

            // Lock and capture
            creditProjectionService.recordMovement(INSTITUTION, 0, CreditMovement.Type.LOCK,
                    new BigDecimal("400.0"), "reservation:RES-ADJ", "lab:LAB-003");
            creditProjectionService.recordMovement(INSTITUTION, 0, CreditMovement.Type.CAPTURE,
                    new BigDecimal("400.0"), "reservation:RES-ADJ", "lab:LAB-003");
            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("400.0"), BigDecimal.ZERO, new BigDecimal("400.0"),
                    BigDecimal.ZERO, BigDecimal.ZERO);

            // Post-capture adjustment: return 100 credits due to service issue
            creditProjectionService.recordMovement(INSTITUTION, 0, CreditMovement.Type.ADJUST,
                    new BigDecimal("100.0"), "reservation:RES-ADJ", "adjustment:service-issue");
            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("400.0"), BigDecimal.ZERO, new BigDecimal("400.0"),
                    new BigDecimal("100.0"), BigDecimal.ZERO);

            CreditAccount afterAdjust = creditProjectionService.getAccount(INSTITUTION).orElseThrow();
            assertThat(afterAdjust.getConsumed()).isEqualByComparingTo("400.0");
            assertThat(afterAdjust.getAdjusted()).isEqualByComparingTo("100.0");

            // Verify movement trail includes ADJUST
            List<CreditMovement> movements = creditProjectionService.getMovements(INSTITUTION, 20);
            assertThat(movements).extracting(CreditMovement::getMovementType)
                    .containsExactly(
                            CreditMovement.Type.ADJUST, CreditMovement.Type.CAPTURE,
                            CreditMovement.Type.LOCK, CreditMovement.Type.MINT);
        }

        @Test
        @DisplayName("expiry and expiry warning behavior")
        void expiryBehavior() {
            // Fund with a lot that expires in the past (simulating late processing)
            FundingOrder order = fundingOrderService.createFundingOrder(
                    INSTITUTION, new BigDecimal("30.00"), new BigDecimal("300.0"), null, null);
            fundingOrderService.issueInvoice(order.getId(), "INV-EXPIRE-001", null);
            fundingOrderService.confirmPayment(order.getId(), "SEPA-EXPIRE-001", new BigDecimal("30.00"), "SEPA");
            fundingOrderService.markCredited(order.getId());

            // Create lot that already expired
            Instant pastExpiry = Instant.now().minus(1, ChronoUnit.DAYS);
            creditProjectionService.syncLot(INSTITUTION, 0, order.getId(),
                    new BigDecimal("30.00"), new BigDecimal("300.0"), new BigDecimal("300.0"),
                    Instant.now().minus(60, ChronoUnit.DAYS), pastExpiry, false);

            // Create lot expiring in the future (should not be expired)
            Instant futureExpiry = Instant.now().plus(30, ChronoUnit.DAYS);
            creditProjectionService.syncLot(INSTITUTION, 1, null,
                    null, new BigDecimal("200.0"), new BigDecimal("200.0"),
                    Instant.now(), futureExpiry, false);

            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("500.0"), BigDecimal.ZERO, BigDecimal.ZERO,
                    BigDecimal.ZERO, BigDecimal.ZERO);

            // Check expiring lots — only the past-expiry lot should be found
            List<CreditLot> expiring = creditProjectionService.getExpiringLots(Instant.now());
            assertThat(expiring).hasSize(1);
            assertThat(expiring.getFirst().getLotIndex()).isEqualTo(0);
            assertThat(expiring.getFirst().getRemaining()).isEqualByComparingTo("300.0");

            // Simulate expiry processing — record EXPIRE movement and mark lot expired
            creditProjectionService.recordMovement(INSTITUTION, 0, CreditMovement.Type.EXPIRE,
                    new BigDecimal("300.0"), null, "auto-expiry");
            creditProjectionService.syncLot(INSTITUTION, 0, order.getId(),
                    new BigDecimal("30.00"), new BigDecimal("300.0"), BigDecimal.ZERO,
                    Instant.now().minus(60, ChronoUnit.DAYS), pastExpiry, true);
            creditProjectionService.syncAccount(INSTITUTION,
                    new BigDecimal("200.0"), BigDecimal.ZERO, BigDecimal.ZERO,
                    BigDecimal.ZERO, new BigDecimal("300.0"));

            // Verify the expired lot is no longer in the expiring query
            List<CreditLot> expiringAfter = creditProjectionService.getExpiringLots(Instant.now());
            assertThat(expiringAfter).isEmpty();

            // Verify account shows expired balance
            CreditAccount afterExpiry = creditProjectionService.getAccount(INSTITUTION).orElseThrow();
            assertThat(afterExpiry.getAvailable()).isEqualByComparingTo("200.0");
            assertThat(afterExpiry.getExpired()).isEqualByComparingTo("300.0");

            // Future lot NOT expired
            List<CreditLot> allLots = creditProjectionService.getLots(INSTITUTION);
            CreditLot futureLot = allLots.stream().filter(l -> l.getLotIndex() == 1).findFirst().orElseThrow();
            assertThat(futureLot.isExpired()).isFalse();
            assertThat(futureLot.getRemaining()).isEqualByComparingTo("200.0");
        }
    }
}
