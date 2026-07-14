package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthTransaction;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;

@ExtendWith(MockitoExtension.class)
class InstitutionalWalletTransactionDispatcherTest {
    @Mock private InstitutionalWalletNonceReservationService nonceReservationService;
    @Mock private WalletService walletService;
    @Mock private Web3j web3j;
    @Mock private Request<?, EthGetTransactionCount> nonceRequest;
    @Mock private Request<?, EthChainId> chainIdRequest;
    @Mock private Request<?, EthSendTransaction> sendRequest;
    @Mock private Request<?, EthGetTransactionReceipt> receiptRequest;
    @Mock private Request<?, EthTransaction> transactionLookupRequest;

    @Test
    void reservesPersistsBroadcastsAndStoresHashInsideOneDispatch() throws Exception {
        EthGetTransactionCount response = new EthGetTransactionCount();
        response.setResult("0x2d");
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        doReturn(chainIdRequest).when(web3j).ethChainId();
        EthChainId chainIdResponse = new EthChainId();
        chainIdResponse.setResult("0xaa36a7");
        when(chainIdRequest.send()).thenReturn(chainIdResponse);
        doReturn(nonceRequest).when(web3j)
            .ethGetTransactionCount(eq("0xwallet"), any(DefaultBlockParameter.class));
        when(nonceRequest.send()).thenReturn(response);
        when(nonceReservationService.reserveAndPersist(
            eq("0xwallet"), eq(BigInteger.valueOf(11155111)), eq(BigInteger.valueOf(45)), any()
        ))
            .thenAnswer(invocation -> {
                BigInteger nonce = BigInteger.valueOf(47);
                invocation.<java.util.function.BiConsumer<BigInteger, BigInteger>>getArgument(3)
                    .accept(BigInteger.valueOf(11155111), nonce);
                return nonce;
            });
        AtomicReference<BigInteger> persistedNonce = new AtomicReference<>();
        AtomicReference<BigInteger> persistedChainId = new AtomicReference<>();
        AtomicReference<String> persistedHash = new AtomicReference<>();
        String expectedHash = "0x" + "a".repeat(64);
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult(expectedHash);
        doReturn(sendRequest).when(web3j).ethSendRawTransaction("0x01");
        when(sendRequest.send()).thenReturn(sendResponse);
        InstitutionalWalletTransactionDispatcher dispatcher =
            new InstitutionalWalletTransactionDispatcher(nonceReservationService, walletService);

        String hash = dispatcher.dispatchPrepared(
            "0xwallet",
            null,
            null,
            (chainId, nonce) -> {
                persistedChainId.set(chainId);
                persistedNonce.set(nonce);
            },
            nonce -> new InstitutionalWalletTransactionDispatcher.PreparedTransaction("0x01", expectedHash),
            prepared -> { assertThat(persistedHash.get()).isNull(); },
            persistedHash::set
        );

        assertThat(persistedNonce.get()).isEqualTo(BigInteger.valueOf(47));
        assertThat(persistedChainId.get()).isEqualTo(BigInteger.valueOf(11155111));
        assertThat(persistedHash.get()).isEqualTo(hash);
    }

    @Test
    void reusesExistingNonceAndClassifiesLostRpcResponseAsUncertain() {
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        doReturn(chainIdRequest).when(web3j).ethChainId();
        EthChainId chainIdResponse = new EthChainId();
        chainIdResponse.setResult("0x1");
        try {
            when(chainIdRequest.send()).thenReturn(chainIdResponse);
        } catch (java.io.IOException ex) {
            throw new AssertionError(ex);
        }
        InstitutionalWalletTransactionDispatcher dispatcher =
            new InstitutionalWalletTransactionDispatcher(nonceReservationService, walletService);

        String hash = "0x" + "b".repeat(64);
        doReturn(sendRequest).when(web3j).ethSendRawTransaction("0x01");
        try {
            when(sendRequest.send()).thenThrow(new java.io.IOException("rpc response lost"));
        } catch (java.io.IOException ex) {
            throw new AssertionError(ex);
        }

        assertThatThrownBy(() -> dispatcher.dispatchPrepared(
            "0xwallet",
            BigInteger.ONE,
            BigInteger.valueOf(48),
            (ignoredChain, ignoredNonce) -> { },
            ignored -> new InstitutionalWalletTransactionDispatcher.PreparedTransaction("0x01", hash),
            ignored -> { },
            ignored -> { }
        )).isInstanceOf(InstitutionalWalletDispatchException.class)
            .hasCauseInstanceOf(java.io.IOException.class);

        verify(nonceReservationService, never()).reserveAndPersist(eq("0xwallet"), any(), any(), any());
    }

    @Test
    void classifiesAllocatorFailureAsPreBroadcastRetryable() {
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        doReturn(chainIdRequest).when(web3j).ethChainId();
        EthChainId chainIdResponse = new EthChainId();
        chainIdResponse.setResult("0x1");
        try {
            when(chainIdRequest.send()).thenReturn(chainIdResponse);
        } catch (java.io.IOException ex) {
            throw new AssertionError(ex);
        }
        doReturn(nonceRequest).when(web3j)
            .ethGetTransactionCount(eq("0xwallet"), any(DefaultBlockParameter.class));
        EthGetTransactionCount pending = new EthGetTransactionCount();
        pending.setResult("0x2");
        try {
            when(nonceRequest.send()).thenReturn(pending);
        } catch (java.io.IOException ex) {
            throw new AssertionError(ex);
        }
        when(nonceReservationService.reserveAndPersist(
            eq("0xwallet"), eq(BigInteger.ONE), eq(BigInteger.valueOf(2)), any()
        )).thenThrow(new IllegalStateException("wallet is blocked"));

        InstitutionalWalletTransactionDispatcher dispatcher =
            new InstitutionalWalletTransactionDispatcher(nonceReservationService, walletService);

        assertThatThrownBy(() -> dispatcher.dispatchPrepared(
            "0xwallet", null, null, (ignoredChain, ignoredNonce) -> { },
            ignored -> new InstitutionalWalletTransactionDispatcher.PreparedTransaction("0x01", "0x" + "c".repeat(64)),
            ignored -> { }, ignored -> { }
        )).isInstanceOf(InstitutionalWalletDispatchException.class)
            .extracting("outcome")
            .isEqualTo(InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED);

        verify(web3j, never()).ethSendRawTransaction(any());
    }

    @Test
    void classifiesPreparationFailureAsPreBroadcastPermanent() throws Exception {
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        doReturn(chainIdRequest).when(web3j).ethChainId();
        EthChainId chainIdResponse = new EthChainId();
        chainIdResponse.setResult("0x1");
        when(chainIdRequest.send()).thenReturn(chainIdResponse);

        InstitutionalWalletTransactionDispatcher dispatcher =
            new InstitutionalWalletTransactionDispatcher(nonceReservationService, walletService);

        assertThatThrownBy(() -> dispatcher.dispatchPrepared(
            "0xwallet", BigInteger.ONE, BigInteger.valueOf(48), (ignoredChain, ignoredNonce) -> { },
            ignored -> { throw new IllegalStateException("signing unavailable"); },
            ignored -> { }, ignored -> { }
        )).isInstanceOf(InstitutionalWalletDispatchException.class)
            .extracting("outcome")
            .isEqualTo(InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT);

        verify(web3j, never()).ethSendRawTransaction(any());
    }

    @Test
    void classifiesRpcPreparationFailureAsPreBroadcastTransient() throws Exception {
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        doReturn(chainIdRequest).when(web3j).ethChainId();
        EthChainId chainIdResponse = new EthChainId();
        chainIdResponse.setResult("0x1");
        when(chainIdRequest.send()).thenReturn(chainIdResponse);

        InstitutionalWalletTransactionDispatcher dispatcher =
            new InstitutionalWalletTransactionDispatcher(nonceReservationService, walletService);

        assertThatThrownBy(() -> dispatcher.dispatchPrepared(
            "0xwallet", BigInteger.ONE, BigInteger.valueOf(48), (ignoredChain, ignoredNonce) -> { },
            ignored -> { throw new IllegalStateException("RPC timeout while estimating gas"); },
            ignored -> { }, ignored -> { }
        )).isInstanceOf(InstitutionalWalletDispatchException.class)
            .extracting("outcome")
            .isEqualTo(InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_TRANSIENT);

        verify(web3j, never()).ethSendRawTransaction(any());
    }

    @Test
    void rebroadcastPreparedLooksUpOriginalHashBeforeSendingPersistedRaw() throws Exception {
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        String previousHash = "0x" + "d".repeat(64);
        EthGetTransactionReceipt missingReceipt = new EthGetTransactionReceipt();
        EthTransaction missingTransaction = new EthTransaction();
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult(previousHash);
        doReturn(receiptRequest).when(web3j).ethGetTransactionReceipt(previousHash);
        doReturn(transactionLookupRequest).when(web3j).ethGetTransactionByHash(previousHash);
        when(receiptRequest.send()).thenReturn(missingReceipt);
        when(transactionLookupRequest.send()).thenReturn(missingTransaction);
        doReturn(sendRequest).when(web3j).ethSendRawTransaction("0xold-raw");
        when(sendRequest.send()).thenReturn(sendResponse);

        InstitutionalWalletTransactionDispatcher dispatcher =
            new InstitutionalWalletTransactionDispatcher(nonceReservationService, walletService);

        String hash = dispatcher.rebroadcastPrepared(
            new InstitutionalWalletTransactionDispatcher.PreparedTransaction("0xold-raw", previousHash)
        );

        assertThat(hash).isEqualTo(previousHash);
        verify(web3j).ethGetTransactionReceipt(previousHash);
        verify(web3j).ethGetTransactionByHash(previousHash);
        verify(web3j).ethSendRawTransaction("0xold-raw");
    }

    @Test
    void rebroadcastPreparedDoesNotSendWhenOriginalTransactionIsAlreadyVisible() throws Exception {
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        String previousHash = "0x" + "e".repeat(64);
        EthGetTransactionReceipt receiptResponse = mock(EthGetTransactionReceipt.class);
        when(receiptResponse.getTransactionReceipt()).thenReturn(java.util.Optional.of(new TransactionReceipt()));
        doReturn(receiptRequest).when(web3j).ethGetTransactionReceipt(previousHash);
        when(receiptRequest.send()).thenReturn(receiptResponse);

        InstitutionalWalletTransactionDispatcher dispatcher =
            new InstitutionalWalletTransactionDispatcher(nonceReservationService, walletService);

        assertThat(dispatcher.rebroadcastPrepared(
            new InstitutionalWalletTransactionDispatcher.PreparedTransaction("0xold-raw", previousHash)
        )).isEqualTo(previousHash);

        verify(web3j, never()).ethGetTransactionByHash(any());
        verify(web3j, never()).ethSendRawTransaction(any());
    }
}
