package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.*;
import decentralabs.blockchain.service.persistence.CreditAccountPersistenceService;
import decentralabs.blockchain.service.persistence.FundingOrderPersistenceService;
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
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("FundingOrderService Tests")
class FundingOrderServiceTest {

    @Mock
    private FundingOrderPersistenceService persistence;

    @Mock
    private CreditAccountPersistenceService creditPersistence;

    private FundingOrderService service;

    private static final String INSTITUTION_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
    private static final BigDecimal EUR_150 = new BigDecimal("150.00");
    private static final BigDecimal CREDITS_150M = new BigDecimal("1500.0");

    @BeforeEach
    void setUp() {
        service = new FundingOrderService(persistence, creditPersistence);
    }

    // ── createFundingOrder ──────────────────────────────────────────────

    @Nested
    @DisplayName("createFundingOrder")
    class CreateFundingOrderTests {

        @Test
        @DisplayName("Creates DRAFT order and persists it")
        void createsDraftOrder() {
            FundingOrder saved = buildOrder(1L, FundingOrder.Status.DRAFT);
            when(persistence.createFundingOrder(any())).thenReturn(saved);

            FundingOrder result = service.createFundingOrder(INSTITUTION_ADDRESS, EUR_150, CREDITS_150M, "REF-001", null);

            assertThat(result.getId()).isEqualTo(1L);
            assertThat(result.getStatus()).isEqualTo(FundingOrder.Status.DRAFT);
            assertThat(result.getEurGrossAmount()).isEqualByComparingTo(EUR_150);
            ArgumentCaptor<FundingOrder> cap = ArgumentCaptor.forClass(FundingOrder.class);
            verify(persistence).createFundingOrder(cap.capture());
            assertThat(cap.getValue().getInstitutionAddress()).isEqualTo(INSTITUTION_ADDRESS.toLowerCase());
        }

        @Test
        @DisplayName("Rejects null institution address")
        void rejectsNullAddress() {
            assertThatThrownBy(() -> service.createFundingOrder(null, EUR_150, CREDITS_150M, null, null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Rejects invalid Ethereum institution address")
        void rejectsInvalidAddress() {
            assertThatThrownBy(() -> service.createFundingOrder("not-an-address", EUR_150, CREDITS_150M, null, null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Rejects zero EUR amount")
        void rejectsZeroEurAmount() {
            assertThatThrownBy(() ->
                    service.createFundingOrder(INSTITUTION_ADDRESS, BigDecimal.ZERO, CREDITS_150M, null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("EUR gross amount");
        }

        @Test
        @DisplayName("Rejects zero credit amount")
        void rejectsZeroCreditAmount() {
            assertThatThrownBy(() ->
                    service.createFundingOrder(INSTITUTION_ADDRESS, EUR_150, BigDecimal.ZERO, null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Credit amount");
        }
    }

    // ── issueInvoice ────────────────────────────────────────────────────

    @Nested
    @DisplayName("issueInvoice")
    class IssueInvoiceTests {

        @Test
        @DisplayName("Issues invoice for a DRAFT order and advances status to INVOICED")
        void issuesInvoiceForDraftOrder() {
            FundingOrder draft = buildOrder(1L, FundingOrder.Status.DRAFT);
            when(persistence.findFundingOrderById(1L)).thenReturn(Optional.of(draft));
            FundingInvoice saved = FundingInvoice.builder()
                    .id(10L).fundingOrderId(1L).invoiceNumber("INV-001").eurAmount(EUR_150)
                    .issuedAt(Instant.now()).status(FundingInvoice.Status.ISSUED).build();
            when(persistence.createFundingInvoice(any())).thenReturn(saved);

            FundingInvoice result = service.issueInvoice(1L, "INV-001", null);

            assertThat(result.getInvoiceNumber()).isEqualTo("INV-001");
            verify(persistence).updateFundingOrderStatus(1L, FundingOrder.Status.INVOICED);
        }

        @Test
        @DisplayName("Rejects issuing invoice for non-DRAFT order")
        void rejectsInvoiceForNonDraftOrder() {
            FundingOrder invoiced = buildOrder(1L, FundingOrder.Status.INVOICED);
            when(persistence.findFundingOrderById(1L)).thenReturn(Optional.of(invoiced));

            assertThatThrownBy(() -> service.issueInvoice(1L, "INV-002", null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("DRAFT");
        }

        @Test
        @DisplayName("Rejects blank invoice number")
        void rejectsBlankInvoiceNumber() {
            FundingOrder draft = buildOrder(1L, FundingOrder.Status.DRAFT);
            when(persistence.findFundingOrderById(1L)).thenReturn(Optional.of(draft));

            assertThatThrownBy(() -> service.issueInvoice(1L, "  ", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Invoice number");
        }

        @Test
        @DisplayName("Throws when funding order not found")
        void throwsWhenOrderNotFound() {
            when(persistence.findFundingOrderById(99L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.issueInvoice(99L, "INV-X", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("99");
        }
    }

    // ── confirmPayment ──────────────────────────────────────────────────

    @Nested
    @DisplayName("confirmPayment — payment reconciliation")
    class ConfirmPaymentTests {

        @Test
        @DisplayName("Confirms payment for INVOICED order and advances to PAID")
        void confirmsPaymentForInvoicedOrder() {
            FundingOrder invoiced = buildOrder(1L, FundingOrder.Status.INVOICED);
            when(persistence.findFundingOrderById(1L)).thenReturn(Optional.of(invoiced));
            PaymentReconciliation saved = PaymentReconciliation.builder()
                    .id(5L).fundingOrderId(1L).paymentRef("WIRE-ABC").eurAmount(EUR_150)
                    .paymentMethod("SEPA").reconciledAt(Instant.now()).build();
            when(persistence.createReconciliation(any())).thenReturn(saved);

            PaymentReconciliation result = service.confirmPayment(1L, "WIRE-ABC", EUR_150, "SEPA");

            assertThat(result.getPaymentRef()).isEqualTo("WIRE-ABC");
            verify(persistence).updateFundingOrderStatus(1L, FundingOrder.Status.PAID);
            verify(creditPersistence).recordMovement(any(CreditMovement.class));
        }

        @Test
        @DisplayName("Idempotency: rejects duplicate confirmPayment on PAID order")
        void rejectsDuplicateConfirmation() {
            FundingOrder paid = buildOrder(1L, FundingOrder.Status.PAID);
            when(persistence.findFundingOrderById(1L)).thenReturn(Optional.of(paid));

            assertThatThrownBy(() -> service.confirmPayment(1L, "WIRE-DUP", EUR_150, "SEPA"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("INVOICED");
        }

        @Test
        @DisplayName("Rejects empty payment reference")
        void rejectsEmptyPaymentRef() {
            FundingOrder invoiced = buildOrder(1L, FundingOrder.Status.INVOICED);
            when(persistence.findFundingOrderById(1L)).thenReturn(Optional.of(invoiced));

            assertThatThrownBy(() -> service.confirmPayment(1L, "", EUR_150, "SEPA"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Payment reference");
        }

        @Test
        @DisplayName("Rejects zero payment amount")
        void rejectsZeroPaymentAmount() {
            FundingOrder invoiced = buildOrder(1L, FundingOrder.Status.INVOICED);
            when(persistence.findFundingOrderById(1L)).thenReturn(Optional.of(invoiced));

            assertThatThrownBy(() -> service.confirmPayment(1L, "WIRE-X", BigDecimal.ZERO, "SEPA"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("amount");
        }
    }

    // ── cancelFundingOrder ──────────────────────────────────────────────

    @Nested
    @DisplayName("cancelFundingOrder")
    class CancelFundingOrderTests {

        @Test
        @DisplayName("Cancels a DRAFT order")
        void cancelsDraftOrder() {
            FundingOrder draft = buildOrder(1L, FundingOrder.Status.DRAFT);
            when(persistence.findFundingOrderById(1L)).thenReturn(Optional.of(draft));

            service.cancelFundingOrder(1L);

            verify(persistence).updateFundingOrderStatus(1L, FundingOrder.Status.CANCELLED);
        }

        @Test
        @DisplayName("Cannot cancel a CREDITED order")
        void cannotCancelCreditedOrder() {
            FundingOrder credited = buildOrder(1L, FundingOrder.Status.CREDITED);
            when(persistence.findFundingOrderById(1L)).thenReturn(Optional.of(credited));

            assertThatThrownBy(() -> service.cancelFundingOrder(1L))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("CREDITED");
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private FundingOrder buildOrder(long id, FundingOrder.Status status) {
        return FundingOrder.builder()
                .id(id)
                .institutionAddress(INSTITUTION_ADDRESS.toLowerCase())
                .eurGrossAmount(EUR_150)
                .creditAmount(CREDITS_150M)
                .status(status)
                .reference("REF-001")
                .build();
    }
}
