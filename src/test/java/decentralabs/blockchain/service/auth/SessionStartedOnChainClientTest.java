package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.PendingNonceFastRawTransactionManager;
import decentralabs.blockchain.service.wallet.WalletService;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.Bool;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.Response;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.EthTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.utils.Numeric;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SessionStartedOnChainClientTest {
    private static final String CONTRACT = "0x2222222222222222222222222222222222222222";
    private static final long CHAIN_ID = 11155111L;
    private static final String VALID_TX_HASH = "0x" + "1".repeat(64);
    private static final String WALLET_PRIVATE_KEY =
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001";

    @Mock
    private WalletService walletService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private SessionStartedAttestationSigner signer;

    @Mock
    private Web3j web3j;

    @InjectMocks
    private SessionStartedOnChainClient client;

    private Credentials credentials;

    @BeforeEach
    void setUp() {
        credentials = Credentials.create(WALLET_PRIVATE_KEY);
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(signer.getDomainChainId()).thenReturn(CHAIN_ID);
        ReflectionTestUtils.setField(client, "contractAddress", CONTRACT);
        ReflectionTestUtils.setField(client, "gasLimit", BigInteger.valueOf(600000));
        ReflectionTestUtils.setField(client, "gasPriceGwei", BigInteger.valueOf(2));
        ReflectionTestUtils.setField(client, "nonceReplacementGasBumpPercent", 15);
    }

    @Test
    void hasSessionStarted_decodesTrueAndFalse() throws Exception {
        stubEthCalls(ethCallResponse(encode(new Bool(true))), ethCallResponse(encode(new Bool(false))));

        assertThat(client.hasSessionStarted("0xabc")).isTrue();
        assertThat(client.hasSessionStarted("0xdef")).isFalse();
    }

    @Test
    void hasSessionStarted_rejectsEmptyAndErrorResponses() throws Exception {
        stubEthCalls((EthCall) null);
        assertThatThrownBy(() -> client.hasSessionStarted("0xabc"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("empty eth_call response");

        stubEthCalls(ethCallError("execution reverted"));
        assertThatThrownBy(() -> client.hasSessionStarted("0xabc"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("execution reverted");
    }

    @Test
    void hasSessionStarted_wrapsRpcIoFailures() throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthCall> request = (Request<?, EthCall>) mock(Request.class);
        doReturn(request).when(web3j).ethCall(any(), eq(DefaultBlockParameterName.LATEST));
        when(request.send()).thenThrow(new IOException("rpc unavailable"));

        assertThatThrownBy(() -> client.hasSessionStarted("0xabc"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Failed to query SessionStarted status: rpc unavailable");
    }

    @Test
    void exposesSignerAndConnectedChainId() throws Exception {
        assertThat(client.signerAddress()).isEqualTo(credentials.getAddress());

        stubChainId(CHAIN_ID);

        assertThat(client.connectedChainId()).isEqualTo(BigInteger.valueOf(CHAIN_ID));
    }

    @Test
    void connectedChainId_rejectsMissingNonPositiveAndRpcFailures() throws Exception {
        stubChainIdResponse(null);
        assertThatThrownBy(() -> client.connectedChainId())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Failed to resolve SessionStarted publication chainId")
            .hasRootCauseMessage("RPC returned no valid SessionStarted chainId");

        stubChainId(0);
        assertThatThrownBy(() -> client.connectedChainId())
            .isInstanceOf(IllegalStateException.class)
            .hasRootCauseMessage("RPC returned no valid SessionStarted chainId");

        @SuppressWarnings("unchecked")
        Request<?, EthChainId> request = (Request<?, EthChainId>) mock(Request.class);
        doReturn(request).when(web3j).ethChainId();
        when(request.send()).thenThrow(new IOException("chain rpc unavailable"));
        assertThatThrownBy(() -> client.connectedChainId())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Failed to resolve SessionStarted publication chainId")
            .hasRootCauseMessage("chain rpc unavailable");
    }

    @Test
    void validateSessionStartedPreflight_runsAgainstMatchingDomain() throws Exception {
        stubChainId(CHAIN_ID);
        stubEthCalls(ethCallResponse("0x"));

        client.validateSessionStartedPreflight(validSubmission());

        verify(web3j).ethCall(any(), eq(DefaultBlockParameterName.LATEST));
    }

    @Test
    void validateSessionStartedPreflight_surfacesContractRevertAndRpcFailures() throws Exception {
        stubChainId(CHAIN_ID);
        stubEthCalls(ethCallError("Session already used"));

        assertThatThrownBy(() -> client.validateSessionStartedPreflight(validSubmission()))
            .isInstanceOf(SessionStartedOnChainClient.SessionStartedPreflightException.class)
            .hasMessageContaining("SessionStarted preflight reverted: Session already used");

        stubChainId(CHAIN_ID);
        @SuppressWarnings("unchecked")
        Request<?, EthCall> request = (Request<?, EthCall>) mock(Request.class);
        doReturn(request).when(web3j).ethCall(any(), eq(DefaultBlockParameterName.LATEST));
        when(request.send()).thenThrow(new IOException("preflight rpc unavailable"));

        assertThatThrownBy(() -> client.validateSessionStartedPreflight(validSubmission()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Failed to run SessionStarted preflight eth_call: preflight rpc unavailable");
    }

    @Test
    void validateSessionStartedPreflight_rejectsChainMismatchAndMissingResponse() throws Exception {
        when(signer.getDomainChainId()).thenReturn(CHAIN_ID + 1);
        stubChainId(CHAIN_ID);

        assertThatThrownBy(() -> client.validateSessionStartedPreflight(validSubmission()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("does not match connected chainId");

        when(signer.getDomainChainId()).thenReturn(CHAIN_ID);
        stubChainId(CHAIN_ID);
        stubEthCalls((EthCall) null);

        assertThatThrownBy(() -> client.validateSessionStartedPreflight(validSubmission()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("RPC returned no SessionStarted preflight response");
    }

    @Test
    void prepareSessionStarted_signsDeterministicTransactionAndAppliesReplacementGas() throws Exception {
        stubChainId(CHAIN_ID);

        InstitutionalWalletTransactionDispatcher.PreparedTransaction first =
            client.prepareSessionStarted(validSubmission(), BigInteger.valueOf(7), 0);
        InstitutionalWalletTransactionDispatcher.PreparedTransaction replacement =
            client.prepareSessionStarted(
                validSubmission(), BigInteger.valueOf(7), 2, BigInteger.valueOf(3_000_000_000L)
            );

        assertThat(first.rawTransaction()).startsWith("0x");
        assertThat(first.transactionHash()).isEqualTo(Hash.sha3(first.rawTransaction()));
        assertThat(first.gasPrice()).isEqualTo(BigInteger.valueOf(2_000_000_000L));
        assertThat(replacement.gasPrice()).isEqualTo(BigInteger.valueOf(3_900_000_000L));
        assertThat(replacement.rawTransaction()).isNotEqualTo(first.rawTransaction());
    }

    @Test
    void prepareSessionStarted_rejectsInvalidSubmissionNonceAndChain() throws Exception {
        assertThatThrownBy(() -> client.prepareSessionStarted(null, BigInteger.ZERO, 0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("SessionStarted submission is required");

        assertThatThrownBy(() -> client.prepareSessionStarted(validSubmission(), null, 0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("SessionStarted transaction nonce is required");
        assertThatThrownBy(() -> client.prepareSessionStarted(validSubmission(), BigInteger.valueOf(-1), 0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("SessionStarted transaction nonce is required");

        stubChainId(0);
        assertThatThrownBy(() -> client.prepareSessionStarted(validSubmission(), BigInteger.ZERO, 0))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("Unable to verify connected chainId for SessionStarted publication");

        stubChainIdResponse(null);
        assertThatThrownBy(() -> client.prepareSessionStarted(validSubmission(), BigInteger.ZERO, 0))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("Unable to verify connected chainId for SessionStarted publication");

        @SuppressWarnings("unchecked")
        Request<?, EthChainId> request = (Request<?, EthChainId>) mock(Request.class);
        doReturn(request).when(web3j).ethChainId();
        when(request.send()).thenThrow(new IOException("chain id unavailable"));
        assertThatThrownBy(() -> client.prepareSessionStarted(validSubmission(), BigInteger.ZERO, 0))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("RPC could not resolve chainId for SessionStarted publication")
            .hasRootCauseMessage("chain id unavailable");
    }

    @Test
    void prepareSessionStarted_validatesAllRequiredTextFields() {
        String[] values = {
            "reservationKey", "labId", "pucHash", "signerAddress", "sessionId",
            "accessType", "nonce", "credentialHash", "signature"
        };

        for (String field : values) {
            SessionStartedOnChainSubmission invalid = submissionWithBlank(field);
            assertThatThrownBy(() -> client.prepareSessionStarted(invalid, BigInteger.ZERO, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SessionStarted " + field + " is required");
        }
    }

    @Test
    void broadcastSignedRawTransaction_returnsExpectedHashAndAllowsKnownTransaction() throws Exception {
        String raw = "0x1234";
        EthSendTransaction accepted = mock(EthSendTransaction.class);
        when(accepted.hasError()).thenReturn(false);
        when(accepted.getTransactionHash()).thenReturn(Hash.sha3(raw));
        stubRawTransactionResponse(accepted);

        assertThat(client.broadcastSignedRawTransaction(raw)).isEqualTo(Hash.sha3(raw));

        EthSendTransaction alreadyKnown = mock(EthSendTransaction.class);
        when(alreadyKnown.hasError()).thenReturn(true);
        when(alreadyKnown.getError()).thenReturn(new Response.Error(1, "already known"));
        stubRawTransactionResponse(alreadyKnown);

        assertThat(client.broadcastSignedRawTransaction(raw)).isEqualTo(Hash.sha3(raw));
    }

    @Test
    void broadcastSignedRawTransaction_rejectsInvalidResponses() throws Exception {
        assertThatThrownBy(() -> client.broadcastSignedRawTransaction(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Signed raw transaction is required");
        assertThatThrownBy(() -> client.broadcastSignedRawTransaction("  "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Signed raw transaction is required");

        EthSendTransaction failed = mock(EthSendTransaction.class);
        when(failed.hasError()).thenReturn(true);
        when(failed.getError()).thenReturn(new Response.Error(1, "execution reverted"));
        stubRawTransactionResponse(failed);
        assertThatThrownBy(() -> client.broadcastSignedRawTransaction("0x1234"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("Transaction broadcast failed: execution reverted");

        EthSendTransaction wrongHash = mock(EthSendTransaction.class);
        when(wrongHash.getTransactionHash()).thenReturn("0x" + "9".repeat(64));
        stubRawTransactionResponse(wrongHash);
        assertThatThrownBy(() -> client.broadcastSignedRawTransaction("0x1234"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("Node returned a hash different from the signed transaction");

        stubRawTransactionResponse(null);
        assertThatThrownBy(() -> client.broadcastSignedRawTransaction("0x1234"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("RPC returned no transaction response");
    }

    @Test
    void broadcastSignedRawTransaction_wrapsRpcIoFailures() throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthSendTransaction> request = (Request<?, EthSendTransaction>) mock(Request.class);
        doReturn(request).when(web3j).ethSendRawTransaction("0x1234");
        when(request.send()).thenThrow(new IOException("broadcast unavailable"));

        assertThatThrownBy(() -> client.broadcastSignedRawTransaction("0x1234"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Failed to broadcast signed SessionStarted transaction");
    }

    @Test
    void markSessionStarted_sendsTransactionWithReplacementGas() throws Exception {
        stubChainId(CHAIN_ID);
        EthSendTransaction response = mock(EthSendTransaction.class);
        when(response.getTransactionHash()).thenReturn(VALID_TX_HASH);
        when(response.hasError()).thenReturn(false);

        try (MockedConstruction<PendingNonceFastRawTransactionManager> construction =
                 mockConstruction(PendingNonceFastRawTransactionManager.class, (mock, context) ->
                     when(mock.sendTransaction(
                         any(), any(), any(), any(), any()
                     )).thenReturn(response))) {

            assertThat(client.markSessionStarted(validSubmission(), BigInteger.valueOf(12), 1))
                .isEqualTo(VALID_TX_HASH);

            assertThat(construction.constructed()).hasSize(1);
            verify(construction.constructed().getFirst()).sendTransaction(
                eq(BigInteger.valueOf(3_000_000_000L)),
                eq(BigInteger.valueOf(600000)),
                eq(CONTRACT),
                any(String.class),
                eq(BigInteger.ZERO)
            );
        }
    }

    @Test
    void markSessionStarted_rejectsMissingHashErrorsAndIoFailures() throws Exception {
        stubChainId(CHAIN_ID);
        EthSendTransaction noHash = mock(EthSendTransaction.class);
        when(noHash.getTransactionHash()).thenReturn(null);
        when(noHash.hasError()).thenReturn(false);

        try (MockedConstruction<PendingNonceFastRawTransactionManager> ignored =
                 mockConstruction(PendingNonceFastRawTransactionManager.class, (mock, context) ->
                     when(mock.sendTransaction(any(), any(), any(), any(), any())).thenReturn(noHash))) {
            assertThatThrownBy(() -> client.markSessionStarted(validSubmission(), BigInteger.ZERO, 0))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("SessionStarted transaction failed: tx_hash_missing");
        }

        stubChainId(CHAIN_ID);
        EthSendTransaction failed = mock(EthSendTransaction.class);
        when(failed.getTransactionHash()).thenReturn(VALID_TX_HASH);
        when(failed.hasError()).thenReturn(true);
        when(failed.getError()).thenReturn(new Response.Error(1, "execution reverted"));
        try (MockedConstruction<PendingNonceFastRawTransactionManager> ignored =
                 mockConstruction(PendingNonceFastRawTransactionManager.class, (mock, context) ->
                     when(mock.sendTransaction(any(), any(), any(), any(), any())).thenReturn(failed))) {
            assertThatThrownBy(() -> client.markSessionStarted(validSubmission(), BigInteger.ZERO, 0))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("SessionStarted transaction failed: execution reverted");
        }

        stubChainId(CHAIN_ID);
        try (MockedConstruction<PendingNonceFastRawTransactionManager> ignored =
                 mockConstruction(PendingNonceFastRawTransactionManager.class, (mock, context) ->
                     when(mock.sendTransaction(any(), any(), any(), any(), any()))
                         .thenThrow(new IOException("write unavailable")))) {
            assertThatThrownBy(() -> client.markSessionStarted(validSubmission(), BigInteger.ZERO, 0))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to send SessionStarted transaction: write unavailable");
        }
    }

    @Test
    void markSessionStarted_rejectsInvalidNonceAndChain() throws Exception {
        assertThatThrownBy(() -> client.markSessionStarted(validSubmission(), null, 0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("SessionStarted transaction nonce is required");
        assertThatThrownBy(() -> client.markSessionStarted(validSubmission(), BigInteger.valueOf(-1), 0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("SessionStarted transaction nonce is required");

        stubChainId(CHAIN_ID);
        when(signer.getDomainChainId()).thenReturn(CHAIN_ID + 1);
        assertThatThrownBy(() -> client.markSessionStarted(validSubmission(), BigInteger.ZERO, 0))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("does not match connected chainId");
    }

    @Test
    void transactionStateStrict_distinguishesPendingSuccessAndFailure() throws Exception {
        EthGetTransactionReceipt pending = mock(EthGetTransactionReceipt.class);
        when(pending.getTransactionReceipt()).thenReturn(Optional.empty());
        stubReceiptResponse(pending);
        assertThat(client.transactionStateStrict(VALID_TX_HASH))
            .isEqualTo(SessionStartedOnChainClient.TransactionState.PENDING);
        assertThat(client.transactionState(VALID_TX_HASH))
            .isEqualTo(SessionStartedOnChainClient.TransactionState.PENDING);

        TransactionReceipt receipt = mock(TransactionReceipt.class);
        EthGetTransactionReceipt succeeded = mock(EthGetTransactionReceipt.class);
        when(succeeded.getTransactionReceipt()).thenReturn(Optional.of(receipt));
        when(receipt.isStatusOK()).thenReturn(true);
        stubReceiptResponse(succeeded);
        assertThat(client.transactionStateStrict(VALID_TX_HASH))
            .isEqualTo(SessionStartedOnChainClient.TransactionState.SUCCEEDED);

        when(receipt.isStatusOK()).thenReturn(false);
        assertThat(client.transactionStateStrict(VALID_TX_HASH))
            .isEqualTo(SessionStartedOnChainClient.TransactionState.FAILED);
    }

    @Test
    void transactionStateStrict_rejectsInvalidHashAndRpcErrors() throws Exception {
        assertThatThrownBy(() -> client.transactionStateStrict("0x1234"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Invalid SessionStarted transaction hash");

        EthGetTransactionReceipt error = mock(EthGetTransactionReceipt.class);
        when(error.hasError()).thenReturn(true);
        when(error.getError()).thenReturn(new Response.Error(1, "receipt unavailable"));
        stubReceiptResponse(error);
        assertThatThrownBy(() -> client.transactionStateStrict(VALID_TX_HASH))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("Failed to inspect SessionStarted transaction")
            .hasRootCauseMessage("RPC returned an error while reading SessionStarted receipt: receipt unavailable");

        stubReceiptResponse(null);
        assertThatThrownBy(() -> client.transactionStateStrict(VALID_TX_HASH))
            .isInstanceOf(IllegalStateException.class)
            .hasRootCauseMessage("Node returned no SessionStarted receipt response");
    }

    @Test
    void transactionState_degradesInspectionFailuresToPending() throws Exception {
        assertThat(client.transactionState("0x1234"))
            .isEqualTo(SessionStartedOnChainClient.TransactionState.PENDING);

        @SuppressWarnings("unchecked")
        Request<?, EthGetTransactionReceipt> request = (Request<?, EthGetTransactionReceipt>) mock(Request.class);
        doReturn(request).when(web3j).ethGetTransactionReceipt(VALID_TX_HASH);
        when(request.send()).thenThrow(new IOException("receipt unavailable"));
        assertThat(client.transactionState(VALID_TX_HASH))
            .isEqualTo(SessionStartedOnChainClient.TransactionState.PENDING);
    }

    @Test
    void transactionVisible_reportsPresenceAndAbsence() throws Exception {
        EthTransaction present = mock(EthTransaction.class);
        when(present.getTransaction()).thenReturn(Optional.of(mock(org.web3j.protocol.core.methods.response.Transaction.class)));
        stubVisibilityResponse(present);
        assertThat(client.transactionVisible(VALID_TX_HASH)).isTrue();

        EthTransaction absent = mock(EthTransaction.class);
        when(absent.getTransaction()).thenReturn(Optional.empty());
        stubVisibilityResponse(absent);
        assertThat(client.transactionVisible(VALID_TX_HASH)).isFalse();
    }

    @Test
    void transactionVisible_rejectsInvalidHashAndRpcErrors() throws Exception {
        assertThatThrownBy(() -> client.transactionVisible("0xnot-a-hash"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Invalid SessionStarted transaction hash");

        EthTransaction error = mock(EthTransaction.class);
        when(error.hasError()).thenReturn(true);
        when(error.getError()).thenReturn(new Response.Error(1, "lookup unavailable"));
        stubVisibilityResponse(error);
        assertThatThrownBy(() -> client.transactionVisible(VALID_TX_HASH))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("Failed to inspect SessionStarted transaction visibility")
            .hasRootCauseMessage("RPC returned an error while reading SessionStarted visibility: lookup unavailable");

        stubVisibilityResponse(null);
        assertThatThrownBy(() -> client.transactionVisible(VALID_TX_HASH))
            .hasRootCauseMessage("Node returned no transaction lookup response");
    }

    @Test
    void pendingNonce_returnsPendingCountAndWrapsFailures() throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthGetTransactionCount> request = (Request<?, EthGetTransactionCount>) mock(Request.class);
        EthGetTransactionCount response = mock(EthGetTransactionCount.class);
        doReturn(request).when(web3j).ethGetTransactionCount(
            credentials.getAddress(), DefaultBlockParameterName.PENDING
        );
        when(request.send()).thenReturn(response);
        when(response.getTransactionCount()).thenReturn(BigInteger.valueOf(42));

        assertThat(client.pendingNonce(credentials.getAddress())).isEqualTo(BigInteger.valueOf(42));

        when(response.getTransactionCount()).thenReturn(null);
        assertThatThrownBy(() -> client.pendingNonce(credentials.getAddress()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("Failed to read SessionStarted signer pending nonce")
            .hasRootCauseMessage("Node returned no pending nonce");
    }

    @Test
    void pendingNonce_wrapsRpcIoFailures() throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthGetTransactionCount> request = (Request<?, EthGetTransactionCount>) mock(Request.class);
        doReturn(request).when(web3j).ethGetTransactionCount("0xwallet", DefaultBlockParameterName.PENDING);
        when(request.send()).thenThrow(new IOException("nonce unavailable"));

        assertThatThrownBy(() -> client.pendingNonce("0xwallet"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Failed to read SessionStarted signer pending nonce")
            .hasRootCauseMessage("nonce unavailable");
    }

    @Test
    void preflightException_classifiesKnownContractReasons() {
        SessionStartedOnChainClient.SessionStartedPreflightException used =
            new SessionStartedOnChainClient.SessionStartedPreflightException("Session already used");
        SessionStartedOnChainClient.SessionStartedPreflightException future =
            new SessionStartedOnChainClient.SessionStartedPreflightException("StartedAt in future");
        SessionStartedOnChainClient.SessionStartedPreflightException other =
            new SessionStartedOnChainClient.SessionStartedPreflightException(null);

        assertThat(used.observationAlreadyUsed()).isTrue();
        assertThat(used.startedAtInFuture()).isFalse();
        assertThat(future.observationAlreadyUsed()).isFalse();
        assertThat(future.startedAtInFuture()).isTrue();
        assertThat(other.observationAlreadyUsed()).isFalse();
        assertThat(other.startedAtInFuture()).isFalse();
    }

    @Test
    void privateValueHelpers_coverReplacementAndHexNormalizationEdges() {
        assertThat((BigInteger) ReflectionTestUtils.invokeMethod(
            client, "gasPriceForReplacement", -2
        )).isEqualTo(BigInteger.valueOf(2));
        ReflectionTestUtils.setField(client, "gasPriceGwei", null);
        ReflectionTestUtils.setField(client, "nonceReplacementGasBumpPercent", -10);
        assertThat((BigInteger) ReflectionTestUtils.invokeMethod(
            client, "gasPriceForReplacement", 2
        )).isEqualTo(BigInteger.ZERO);
        assertThat((BigInteger) ReflectionTestUtils.invokeMethod(
            client, "gasPriceWeiForReplacement", 1, BigInteger.ZERO
        )).isEqualTo(BigInteger.ZERO);
        assertThat((BigInteger) ReflectionTestUtils.invokeMethod(
            client, "toWei", new Object[] { null }
        )).isEqualTo(BigInteger.ZERO);

        assertThat((byte[]) ReflectionTestUtils.invokeMethod(client, "toBytes32", (String) null))
            .containsExactly(new byte[32]);
        assertThat((byte[]) ReflectionTestUtils.invokeMethod(client, "toBytes32", "0xabc"))
            .endsWith((byte) 0x0a, (byte) 0xbc);
        assertThat((byte[]) ReflectionTestUtils.invokeMethod(client, "toBytes32", "0x" + "11".repeat(33)))
            .hasSize(32)
            .containsOnly((byte) 0x11);
        assertThat((String) ReflectionTestUtils.invokeMethod(client, "normalizeAddress", " 0xAbC "))
            .isEqualTo("0x0000000000000000000000000000000000000abc");
        assertThat((String) ReflectionTestUtils.invokeMethod(
            client, "normalizeAddress", "0x" + "11".repeat(21)
        )).isEqualTo("0x" + "11".repeat(20));
        assertThat((String) ReflectionTestUtils.invokeMethod(client, "normalizeAddress", (String) null))
            .isEqualTo("0x0000000000000000000000000000000000000000");
        assertThat((String) ReflectionTestUtils.invokeMethod(client, "nullToEmpty", (String) null))
            .isEmpty();
    }

    private SessionStartedOnChainSubmission validSubmission() {
        return new SessionStartedOnChainSubmission(
            1L,
            "0x" + "01".repeat(32),
            "lab-a",
            "0x" + "02".repeat(32),
            credentials.getAddress(),
            "gateway-a",
            "session-a",
            "desktop",
            1_700_000_000L,
            "0x" + "03".repeat(32),
            "0x" + "04".repeat(32),
            "0x" + "05".repeat(32),
            "0x" + "06".repeat(65)
        );
    }

    private SessionStartedOnChainSubmission submissionWithBlank(String field) {
        SessionStartedOnChainSubmission valid = validSubmission();
        return new SessionStartedOnChainSubmission(
            valid.id(),
            valueOrBlank(field, "reservationKey", valid.reservationKey()),
            valueOrBlank(field, "labId", valid.labId()),
            valueOrBlank(field, "pucHash", valid.pucHash()),
            valueOrBlank(field, "signerAddress", valid.signerAddress()),
            valid.gatewayId(),
            valueOrBlank(field, "sessionId", valid.sessionId()),
            valueOrBlank(field, "accessType", valid.accessType()),
            valid.startedAt(),
            valueOrBlank(field, "nonce", valid.nonce()),
            valueOrBlank(field, "credentialHash", valid.credentialHash()),
            valid.clientProofHash(),
            valueOrBlank(field, "signature", valid.signature())
        );
    }

    private String valueOrBlank(String requestedField, String field, String value) {
        return requestedField.equals(field) ? " " : value;
    }

    private void stubChainId(long chainId) throws Exception {
        stubChainIdResponse(BigInteger.valueOf(chainId));
    }

    private void stubChainIdResponse(BigInteger chainId) throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthChainId> request = (Request<?, EthChainId>) mock(Request.class);
        EthChainId response = mock(EthChainId.class);
        doReturn(request).when(web3j).ethChainId();
        when(request.send()).thenReturn(response);
        when(response.getChainId()).thenReturn(chainId);
    }

    private void stubEthCalls(EthCall... responses) throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthCall>[] requests = new Request[responses.length];
        for (int i = 0; i < responses.length; i++) {
            @SuppressWarnings("unchecked")
            Request<?, EthCall> request = (Request<?, EthCall>) mock(Request.class);
            requests[i] = request;
            when(requests[i].send()).thenReturn(responses[i]);
        }
        AtomicInteger index = new AtomicInteger();
        doAnswer(invocation -> requests[Math.min(index.getAndIncrement(), requests.length - 1)])
            .when(web3j).ethCall(any(), eq(DefaultBlockParameterName.LATEST));
    }

    private void stubRawTransactionResponse(EthSendTransaction response) throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthSendTransaction> request = (Request<?, EthSendTransaction>) mock(Request.class);
        doReturn(request).when(web3j).ethSendRawTransaction("0x1234");
        when(request.send()).thenReturn(response);
    }

    private void stubReceiptResponse(EthGetTransactionReceipt response) throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthGetTransactionReceipt> request = (Request<?, EthGetTransactionReceipt>) mock(Request.class);
        doReturn(request).when(web3j).ethGetTransactionReceipt(VALID_TX_HASH);
        when(request.send()).thenReturn(response);
    }

    private void stubVisibilityResponse(EthTransaction response) throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthTransaction> request = (Request<?, EthTransaction>) mock(Request.class);
        doReturn(request).when(web3j).ethGetTransactionByHash(VALID_TX_HASH);
        when(request.send()).thenReturn(response);
    }

    private EthCall ethCallResponse(String value) {
        EthCall response = new EthCall();
        response.setResult(value);
        return response;
    }

    private EthCall ethCallError(String message) {
        EthCall response = new EthCall();
        response.setError(new Response.Error(1, message));
        return response;
    }

    private String encode(Bool value) {
        return Numeric.prependHexPrefix(TypeEncoder.encode(value));
    }
}
