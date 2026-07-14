package decentralabs.blockchain.service.wallet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.eq;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.EthTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;

@ExtendWith(MockitoExtension.class)
class InstitutionalTransactionOutboxMonitorTest {
    private static final Credentials CREDENTIALS = Credentials.create(
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001"
    );
    @Mock private InstitutionalTransactionOutboxService outboxService;
    @Mock private WalletService walletService;
    @Mock private InstitutionalWalletService institutionalWalletService;
    @Mock private Web3j web3j;

    @BeforeEach
    void currentWalletAndChainAreConfigured() throws Exception {
        EthChainId chainId = mock(EthChainId.class);
        when(chainId.getChainId()).thenReturn(BigInteger.valueOf(11155111L));
        doReturn(requestReturning(chainId)).when(web3j).ethChainId();
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(CREDENTIALS.getAddress());
    }

    @Test
    void marksSubmittedTransactionAsMinedSuccessWhenReceiptIsSuccessful() throws Exception {
        var attempt = attempt("SUBMITTED", "0x" + "a".repeat(64), null);
        EthGetTransactionReceipt receiptResponse = mock(EthGetTransactionReceipt.class);
        TransactionReceipt receipt = mock(TransactionReceipt.class);
        when(receiptResponse.getTransactionReceipt()).thenReturn(Optional.of(receipt));
        when(receipt.isStatusOK()).thenReturn(true);
        doReturn(requestReturning(receiptResponse)).when(web3j)
            .ethGetTransactionReceipt(attempt.txHash());

        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markMinedSuccess(attempt);
    }

    @Test
    void rebroadcastsUnknownTransactionUsingItsPersistedRawTransactionAndNonce() throws Exception {
        var attempt = attempt("STUCK_UNKNOWN", "0x" + "b".repeat(64), "0xf861");
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));

        EthGetTransactionCount nonceResponse = mock(EthGetTransactionCount.class);
        when(nonceResponse.getTransactionCount()).thenReturn(BigInteger.valueOf(14));
        doReturn(requestReturning(nonceResponse)).when(web3j)
            .ethGetTransactionCount(attempt.walletAddress(), org.web3j.protocol.core.DefaultBlockParameterName.PENDING);
        mockMissingTransaction(attempt);
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult("0x" + "c".repeat(64));
        doReturn(requestReturning(sendResponse)).when(web3j).ethSendRawTransaction(attempt.signedRawTransaction());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markSubmitted(attempt, "0x" + "c".repeat(64));
    }

    @Test
    void resolvesStuckUnknownFromReceiptBeforeReadingPendingNonce() throws Exception {
        var attempt = attempt("STUCK_UNKNOWN", "0x" + "1".repeat(64), "0xf861");
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));

        EthGetTransactionReceipt receiptResponse = mock(EthGetTransactionReceipt.class);
        TransactionReceipt receipt = mock(TransactionReceipt.class);
        when(receiptResponse.getTransactionReceipt()).thenReturn(Optional.of(receipt));
        when(receipt.isStatusOK()).thenReturn(true);
        doReturn(requestReturning(receiptResponse)).when(web3j)
            .ethGetTransactionReceipt(attempt.txHash());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markMinedSuccess(attempt);
        verify(web3j, org.mockito.Mockito.never()).ethGetTransactionByHash(any());
        verify(web3j, org.mockito.Mockito.never()).ethGetTransactionCount(any(), any());
        verify(web3j, org.mockito.Mockito.never()).ethSendRawTransaction(any());
    }

    @Test
    void returnsVisibleStuckUnknownToSubmittedMonitoring() throws Exception {
        var attempt = attempt("STUCK_UNKNOWN", "0x" + "2".repeat(64), "0xf861");
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));
        mockMissingReceipt(attempt);
        EthTransaction transactionResponse = mock(EthTransaction.class);
        when(transactionResponse.getTransaction()).thenReturn(Optional.of(mock(org.web3j.protocol.core.methods.response.Transaction.class)));
        doReturn(requestReturning(transactionResponse)).when(web3j).ethGetTransactionByHash(attempt.txHash());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(web3j, org.mockito.Mockito.never()).ethGetTransactionCount(any(), any());
        verify(web3j, org.mockito.Mockito.never()).ethSendRawTransaction(any());
        verify(outboxService).markSubmitted(attempt, attempt.txHash());
    }

    @Test
    void stopsRetryingWhenGenericAttemptExceedsConfiguredBudget() throws Exception {
        var attempt = attempt("RETRYABLE", "0x" + "3".repeat(64), "0xf861");
        attempt = new InstitutionalTransactionOutboxService.Attempt(
            attempt.id(), attempt.chainId(), attempt.walletAddress(), attempt.operationKey(), attempt.nonce(),
            attempt.gasPrice(), attempt.gasLimit(), attempt.toAddress(), attempt.value(), attempt.data(),
            attempt.status(), attempt.signedRawTransaction(), attempt.txHash(), Instant.now().minusSeconds(30),
            3, Instant.now().minusSeconds(30)
        );
        when(outboxService.findRecoveryCandidates(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );
        ReflectionTestUtils.setField(monitor, "maxAttempts", 3);

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markStuckUnknown(
            attempt, "Institutional transaction exceeded the retry budget; manual intervention required"
        );
        verify(web3j, org.mockito.Mockito.never()).ethSendRawTransaction(any());
    }

    @Test
    void bumpsGasForRetryableReplacementWithoutChangingNonce() throws Exception {
        var base = attempt("RETRYABLE", "0x" + "4".repeat(64), "0xf861");
        var attempt = new InstitutionalTransactionOutboxService.Attempt(
            base.id(), base.chainId(), base.walletAddress(), base.operationKey(), base.nonce(),
            base.gasPrice(), base.gasLimit(), base.toAddress(), base.value(), base.data(), base.status(),
            base.signedRawTransaction(), base.txHash(), Instant.now(), 1, Instant.now()
        );
        when(outboxService.findRecoveryCandidates(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);
        EthGetTransactionReceipt emptyReceipt = mock(EthGetTransactionReceipt.class);
        when(emptyReceipt.getTransactionReceipt()).thenReturn(Optional.empty());
        doReturn(requestReturning(emptyReceipt)).when(web3j).ethGetTransactionReceipt(any());
        EthTransaction emptyTransaction = mock(EthTransaction.class);
        when(emptyTransaction.getTransaction()).thenReturn(Optional.empty());
        doReturn(requestReturning(emptyTransaction)).when(web3j).ethGetTransactionByHash(any());
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult("0x" + "5".repeat(64));
        doReturn(requestReturning(sendResponse)).when(web3j).ethSendRawTransaction(any());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );
        ReflectionTestUtils.setField(monitor, "gasBumpPercent", 20);

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markReplacementPrepared(
            eq(attempt), eq(attempt.txHash()), any(), any(), eq(BigInteger.valueOf(2))
        );
        verify(outboxService).markSubmitted(attempt, "0x" + "5".repeat(64));
    }

    @Test
    void calculatesReplacementGasFromOriginalPriceInsteadOfCurrentPrice() throws Exception {
        var base = attemptWithGasPrices(
            "RETRYABLE", "0x" + "6".repeat(64), "0xf861", BigInteger.ONE, BigInteger.valueOf(2)
        );
        var attempt = new InstitutionalTransactionOutboxService.Attempt(
            base.id(), base.chainId(), base.walletAddress(), base.operationKey(), base.nonce(),
            base.originalGasPrice(), base.currentGasPrice(), base.gasLimit(), base.toAddress(), base.value(),
            base.data(), base.status(), base.signedRawTransaction(), base.txHash(), Instant.now(), 2,
            Instant.now()
        );
        when(outboxService.findRecoveryCandidates(any(), any(), org.mockito.ArgumentMatchers.eq(10)))
            .thenReturn(List.of(attempt));
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);
        mockMissingTransaction(attempt);
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult("0x" + "7".repeat(64));
        doReturn(requestReturning(sendResponse)).when(web3j).ethSendRawTransaction(any());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );
        ReflectionTestUtils.setField(monitor, "gasBumpPercent", 20);

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markReplacementPrepared(
            eq(attempt), eq(attempt.txHash()), any(), any(), eq(BigInteger.valueOf(2))
        );
    }

    @Test
    void capsReplacementGasByConfiguredPriceMultiplierAndTransactionCost() throws Exception {
        var base = attemptWithGasPrices(
            "RETRYABLE", "0x" + "8".repeat(64), "0xf861", BigInteger.TEN, BigInteger.valueOf(20)
        );
        var attempt = new InstitutionalTransactionOutboxService.Attempt(
            base.id(), base.chainId(), base.walletAddress(), base.operationKey(), base.nonce(),
            base.originalGasPrice(), base.currentGasPrice(), base.gasLimit(), base.toAddress(), base.value(),
            base.data(), base.status(), base.signedRawTransaction(), base.txHash(), Instant.now(), 10,
            Instant.now()
        );
        when(outboxService.findRecoveryCandidates(any(), any(), org.mockito.ArgumentMatchers.eq(10)))
            .thenReturn(List.of(attempt));
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);
        mockMissingTransaction(attempt);
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult("0x" + "9".repeat(64));
        doReturn(requestReturning(sendResponse)).when(web3j).ethSendRawTransaction(any());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );
        ReflectionTestUtils.setField(monitor, "gasBumpPercent", 20);
        ReflectionTestUtils.setField(monitor, "maxMultiplier", new java.math.BigDecimal("2"));
        ReflectionTestUtils.setField(monitor, "maxGasPriceWei", BigInteger.valueOf(18));
        ReflectionTestUtils.setField(monitor, "maxEstimatedTransactionCost", BigInteger.valueOf(378_000));
        ReflectionTestUtils.setField(monitor, "maxAttempts", 20);

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markReplacementPrepared(
            eq(attempt), eq(attempt.txHash()), any(), any(), eq(BigInteger.valueOf(18))
        );
    }

    @Test
    void marksStaleSubmittedTransactionUnknownWhenNonceHasNotAdvanced() throws Exception {
        var attempt = attempt("SUBMITTED", "0x" + "e".repeat(64), "0xf861", Instant.now().minusSeconds(600));
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());

        EthGetTransactionReceipt receiptResponse = mock(EthGetTransactionReceipt.class);
        when(receiptResponse.getTransactionReceipt()).thenReturn(Optional.empty());
        doReturn(requestReturning(receiptResponse)).when(web3j).ethGetTransactionReceipt(attempt.txHash());
        EthTransaction transactionResponse = mock(EthTransaction.class);
        when(transactionResponse.getTransaction()).thenReturn(Optional.empty());
        doReturn(requestReturning(transactionResponse)).when(web3j).ethGetTransactionByHash(attempt.txHash());
        EthGetTransactionCount nonceResponse = mock(EthGetTransactionCount.class);
        when(nonceResponse.getTransactionCount()).thenReturn(attempt.nonce());
        doReturn(requestReturning(nonceResponse)).when(web3j)
            .ethGetTransactionCount(attempt.walletAddress(), org.web3j.protocol.core.DefaultBlockParameterName.PENDING);

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);
        verify(outboxService).markStuckUnknown(
            attempt, "Submitted transaction is no longer visible and the node has not consumed its nonce"
        );
    }

    @Test
    void claimsAVisibleStaleSubmittedTransactionForReplacement() throws Exception {
        var attempt = attempt("SUBMITTED", "0x" + "1".repeat(64), "0xf861", Instant.now().minusSeconds(600));
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        mockMissingReceipt(attempt);
        EthTransaction transactionResponse = mock(EthTransaction.class);
        when(transactionResponse.getTransaction()).thenReturn(Optional.of(
            mock(org.web3j.protocol.core.methods.response.Transaction.class)
        ));
        doReturn(requestReturning(transactionResponse)).when(web3j).ethGetTransactionByHash(attempt.txHash());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markReplacementPending(
            attempt, "Submitted transaction remained visible without a receipt; replacement required"
        );
        verify(web3j, org.mockito.Mockito.never()).ethGetTransactionCount(any(), any());
    }

    @Test
    void broadcastsBoundedReplacementForVisibleStaleTransactionAndPreservesNonce() throws Exception {
        var attempt = new InstitutionalTransactionOutboxService.Attempt(
            1L, BigInteger.valueOf(11155111L), CREDENTIALS.getAddress(), "operation-key", BigInteger.valueOf(14),
            BigInteger.ONE, BigInteger.ONE, BigInteger.valueOf(21_000), "0xto", BigInteger.ZERO, "0x",
            "REPLACEMENT_PENDING", "0xf861", "0x" + "2".repeat(64),
            Instant.now().minusSeconds(600), 0, Instant.now().minusSeconds(600)
        );
        when(outboxService.findRecoveryCandidates(any(), any(), org.mockito.ArgumentMatchers.eq(10)))
            .thenReturn(List.of(attempt));
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);
        mockMissingTransaction(attempt);
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult("0x" + "3".repeat(64));
        doReturn(requestReturning(sendResponse)).when(web3j).ethSendRawTransaction(any());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );
        ReflectionTestUtils.setField(monitor, "gasBumpPercent", 20);

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markReplacementPrepared(
            eq(attempt), eq(attempt.txHash()), any(), any(), eq(BigInteger.valueOf(2))
        );
        verify(outboxService).markSubmitted(attempt, "0x" + "3".repeat(64));
        verify(web3j).ethSendRawTransaction(any());
    }

    @Test
    void reconcilesAReceiptFoundUnderAReplacedHash() throws Exception {
        String currentHash = "0x" + "4".repeat(64);
        String replacedHash = "0x" + "5".repeat(64);
        var attempt = attempt("SUBMITTED", currentHash, "0xf861", Instant.now());
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findReplacedHashes(attempt.id())).thenReturn(List.of(replacedHash));

        EthGetTransactionReceipt missingReceipt = mock(EthGetTransactionReceipt.class);
        when(missingReceipt.getTransactionReceipt()).thenReturn(Optional.empty());
        doReturn(requestReturning(missingReceipt)).when(web3j).ethGetTransactionReceipt(currentHash);
        EthGetTransactionReceipt minedReceipt = mock(EthGetTransactionReceipt.class);
        TransactionReceipt receipt = mock(TransactionReceipt.class);
        when(minedReceipt.getTransactionReceipt()).thenReturn(Optional.of(receipt));
        when(receipt.isStatusOK()).thenReturn(true);
        doReturn(requestReturning(minedReceipt)).when(web3j).ethGetTransactionReceipt(replacedHash);

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markMinedSuccess(attempt);
        verify(web3j, org.mockito.Mockito.never()).ethGetTransactionByHash(any());
    }

    @Test
    void doesNotTreatARecentlySubmittedInvisibleTransactionAsMissing() throws Exception {
        var attempt = attempt("SUBMITTED", "0x" + "f".repeat(64), "0xf861", Instant.now());
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        EthGetTransactionReceipt receiptResponse = mock(EthGetTransactionReceipt.class);
        when(receiptResponse.getTransactionReceipt()).thenReturn(Optional.empty());
        doReturn(requestReturning(receiptResponse)).when(web3j).ethGetTransactionReceipt(attempt.txHash());
        EthTransaction transactionResponse = mock(EthTransaction.class);
        when(transactionResponse.getTransaction()).thenReturn(Optional.empty());
        doReturn(requestReturning(transactionResponse)).when(web3j).ethGetTransactionByHash(attempt.txHash());
        EthGetTransactionCount nonceResponse = mock(EthGetTransactionCount.class);
        when(nonceResponse.getTransactionCount()).thenReturn(attempt.nonce());
        doReturn(requestReturning(nonceResponse)).when(web3j)
            .ethGetTransactionCount(attempt.walletAddress(), org.web3j.protocol.core.DefaultBlockParameterName.PENDING);

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );
        ReflectionTestUtils.setField(monitor, "submittedStaleAfterMs", 120_000L);

        assertThat(monitor.monitor(web3j, 10)).isZero();
        org.mockito.Mockito.verify(outboxService, org.mockito.Mockito.never())
            .markStuckUnknown(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void reconstructsReservedTransactionAfterRestartBeforeBroadcasting() throws Exception {
        var attempt = attempt("RESERVED", null, null, Instant.now().minusSeconds(1800));
        when(outboxService.findRecoveryCandidates(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);

        EthGetTransactionReceipt receiptResponse = mock(EthGetTransactionReceipt.class);
        when(receiptResponse.getTransactionReceipt()).thenReturn(Optional.empty());
        doReturn(requestReturning(receiptResponse)).when(web3j).ethGetTransactionReceipt(any());
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult("0x" + "d".repeat(64));
        doReturn(requestReturning(sendResponse)).when(web3j).ethSendRawTransaction(any());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markSigned(any(), any(), any());
        verify(outboxService).markSubmitted(attempt, "0x" + "d".repeat(64));
    }

    @Test
    void recoversLegacyUnknownRowWithoutHashByReconstructingItsMaterial() throws Exception {
        var attempt = attempt("STUCK_UNKNOWN", null, null, Instant.now().minusSeconds(1800));
        when(outboxService.findRecoveryCandidates(any(), any(), org.mockito.ArgumentMatchers.eq(10)))
            .thenReturn(List.of(attempt));
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);
        EthGetTransactionReceipt receiptResponse = mock(EthGetTransactionReceipt.class);
        when(receiptResponse.getTransactionReceipt()).thenReturn(Optional.empty());
        doReturn(requestReturning(receiptResponse)).when(web3j).ethGetTransactionReceipt(any());
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult("0x" + "a".repeat(64));
        doReturn(requestReturning(sendResponse)).when(web3j).ethSendRawTransaction(any());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markSigned(any(), any(), any());
        verify(outboxService).markSubmitted(attempt, "0x" + "a".repeat(64));
    }

    @Test
    void ignoresOutboxRowsFromAnotherChainOrWallet() {
        var attempt = new InstitutionalTransactionOutboxService.Attempt(
            2L, BigInteger.ONE, "0x0000000000000000000000000000000000000001", "operation-key",
            BigInteger.valueOf(14), BigInteger.ONE, BigInteger.valueOf(21_000), "0xto", BigInteger.ZERO,
            "0x", "RESERVED", null, null, Instant.now()
        );
        when(outboxService.findRecoveryCandidates(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of(attempt));
        when(outboxService.findSubmitted(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());
        when(outboxService.findStuckUnknown(any(), any(), org.mockito.ArgumentMatchers.eq(10))).thenReturn(List.of());

        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isZero();
        verify(institutionalWalletService, org.mockito.Mockito.never()).getInstitutionalCredentials();
        verify(web3j, org.mockito.Mockito.never()).ethSendRawTransaction(any());
    }

    private InstitutionalTransactionOutboxService.Attempt attempt(String status, String hash, String raw) {
        return attempt(status, hash, raw, Instant.now());
    }

    private InstitutionalTransactionOutboxService.Attempt attempt(
        String status, String hash, String raw, Instant updatedAt
    ) {
        return new InstitutionalTransactionOutboxService.Attempt(
            1L, BigInteger.valueOf(11155111L), CREDENTIALS.getAddress(), "operation-key", BigInteger.valueOf(14),
            BigInteger.ONE, BigInteger.valueOf(21_000), "0xto", BigInteger.ZERO, "0x", status, raw, hash, updatedAt
        );
    }

    private InstitutionalTransactionOutboxService.Attempt attemptWithGasPrices(
        String status, String hash, String raw, BigInteger originalGasPrice, BigInteger currentGasPrice
    ) {
        return new InstitutionalTransactionOutboxService.Attempt(
            1L, BigInteger.valueOf(11155111L), CREDENTIALS.getAddress(), "operation-key", BigInteger.valueOf(14),
            originalGasPrice, currentGasPrice, BigInteger.valueOf(21_000), "0xto", BigInteger.ZERO, "0x",
            status, raw, hash, Instant.now(), 0, Instant.now()
        );
    }

    private void mockMissingReceipt(InstitutionalTransactionOutboxService.Attempt attempt) throws Exception {
        EthGetTransactionReceipt receiptResponse = mock(EthGetTransactionReceipt.class);
        when(receiptResponse.getTransactionReceipt()).thenReturn(Optional.empty());
        doReturn(requestReturning(receiptResponse)).when(web3j)
            .ethGetTransactionReceipt(any());
    }

    private void mockMissingTransaction(InstitutionalTransactionOutboxService.Attempt attempt) throws Exception {
        mockMissingReceipt(attempt);
        EthTransaction transactionResponse = mock(EthTransaction.class);
        when(transactionResponse.getTransaction()).thenReturn(Optional.empty());
        doReturn(requestReturning(transactionResponse)).when(web3j)
            .ethGetTransactionByHash(any());
    }

    private static <T extends org.web3j.protocol.core.Response<?>> Request<?, T> requestReturning(T response) {
        return new Request<Object, T>() {
            @Override
            public T send() {
                return response;
            }
        };
    }
}
