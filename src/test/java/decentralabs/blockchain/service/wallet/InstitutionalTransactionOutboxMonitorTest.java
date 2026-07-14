package decentralabs.blockchain.service.wallet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
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

    @Test
    void marksSubmittedTransactionAsMinedSuccessWhenReceiptIsSuccessful() throws Exception {
        var attempt = attempt("SUBMITTED", "0x" + "a".repeat(64), null);
        EthGetTransactionReceipt receiptResponse = mock(EthGetTransactionReceipt.class);
        TransactionReceipt receipt = mock(TransactionReceipt.class);
        when(receiptResponse.getTransactionReceipt()).thenReturn(Optional.of(receipt));
        when(receipt.isStatusOK()).thenReturn(true);
        doReturn(requestReturning(receiptResponse)).when(web3j)
            .ethGetTransactionReceipt(attempt.txHash());

        when(outboxService.findSubmitted(10)).thenReturn(List.of(attempt));
        when(outboxService.findStuckUnknown(10)).thenReturn(List.of());
        InstitutionalTransactionOutboxMonitor monitor = new InstitutionalTransactionOutboxMonitor(
            outboxService, walletService, institutionalWalletService
        );

        assertThat(monitor.monitor(web3j, 10)).isEqualTo(1);

        verify(outboxService).markMinedSuccess(attempt);
    }

    @Test
    void rebroadcastsUnknownTransactionUsingItsPersistedRawTransactionAndNonce() throws Exception {
        var attempt = attempt("STUCK_UNKNOWN", "0x" + "b".repeat(64), "0xf861");
        when(outboxService.findSubmitted(10)).thenReturn(List.of());
        when(outboxService.findStuckUnknown(10)).thenReturn(List.of(attempt));

        EthGetTransactionCount nonceResponse = mock(EthGetTransactionCount.class);
        when(nonceResponse.getTransactionCount()).thenReturn(BigInteger.valueOf(14));
        doReturn(requestReturning(nonceResponse)).when(web3j)
            .ethGetTransactionCount(attempt.walletAddress(), org.web3j.protocol.core.DefaultBlockParameterName.PENDING);
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
    void reconstructsReservedTransactionAfterRestartBeforeBroadcasting() throws Exception {
        var attempt = attempt("RESERVED", null, null);
        when(outboxService.findRecoveryCandidates(10)).thenReturn(List.of(attempt));
        when(outboxService.findSubmitted(10)).thenReturn(List.of());
        when(outboxService.findStuckUnknown(10)).thenReturn(List.of());
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

    private InstitutionalTransactionOutboxService.Attempt attempt(String status, String hash, String raw) {
        return new InstitutionalTransactionOutboxService.Attempt(
            1L, BigInteger.valueOf(11155111L), CREDENTIALS.getAddress(), "operation-key", BigInteger.valueOf(14),
            BigInteger.ONE, BigInteger.valueOf(21_000), "0xto", BigInteger.ZERO, "0x",
            status, raw, hash
        );
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
