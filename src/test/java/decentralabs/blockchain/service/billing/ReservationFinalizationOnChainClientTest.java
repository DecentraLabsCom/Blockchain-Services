package decentralabs.blockchain.service.billing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.service.auth.InstitutionalWalletTransactionDispatcher;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.utils.Numeric;

@ExtendWith(MockitoExtension.class)
class ReservationFinalizationOnChainClientTest {
    private static final String CONTRACT = "0x2222222222222222222222222222222222222222";
    private static final String WALLET_PRIVATE_KEY =
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001";

    @Mock
    private WalletService walletService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private Web3j web3j;

    private ReservationFinalizationOnChainClient client;

    @BeforeEach
    void setUp() {
        client = new ReservationFinalizationOnChainClient(walletService, institutionalWalletService);
        lenient().when(walletService.getWeb3jInstance()).thenReturn(web3j);
        lenient().when(institutionalWalletService.getInstitutionalCredentials())
            .thenReturn(Credentials.create(WALLET_PRIVATE_KEY));
        ReflectionTestUtils.setField(client, "contractAddress", CONTRACT);
        ReflectionTestUtils.setField(client, "gasLimit", BigInteger.valueOf(5_000_000));
        ReflectionTestUtils.setField(client, "gasPriceGwei", BigInteger.valueOf(2));
        ReflectionTestUtils.setField(client, "nonceReplacementGasBumpPercent", 15);
    }

    @Test
    void candidateWorkRequiresAnExpiredValidHeapRoot() {
        assertThat(new ReservationFinalizationOnChainClient.FinalizationStatus(
            BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, BigInteger.valueOf(99), BigInteger.ZERO
        ).hasCandidateWork(100)).isTrue();
        assertThat(new ReservationFinalizationOnChainClient.FinalizationStatus(
            BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, BigInteger.valueOf(101), BigInteger.ZERO
        ).hasCandidateWork(100)).isFalse();
        assertThat(new ReservationFinalizationOnChainClient.FinalizationStatus(
            BigInteger.ONE, BigInteger.TEN, BigInteger.TEN, BigInteger.valueOf(99), BigInteger.ZERO
        ).hasCandidateWork(100)).isFalse();
    }

    @Test
    void encodedCallUsesThePermissionlessFinalizerSignature() {
        BigInteger labId = BigInteger.valueOf(7);
        BigInteger maxBatch = BigInteger.TEN;

        assertThat(client.encodedCall(labId, maxBatch))
            .isEqualTo(FunctionEncoder.encode(
                decentralabs.blockchain.contract.Diamond.finalizeEligibleReservationsFunction(labId, maxBatch)
            ));
    }

    @Test
    void readStatusDecodesBoundedOnChainSignals() throws Exception {
        EthCall response = new EthCall();
        response.setResult(Numeric.prependHexPrefix(String.join("", List.of(
            TypeEncoder.encode(new Uint256(3)),
            TypeEncoder.encode(new Uint256(8)),
            TypeEncoder.encode(new Uint256(2)),
            TypeEncoder.encode(new Uint256(1234)),
            TypeEncoder.encode(new Uint64(1200))
        ))));
        @SuppressWarnings("unchecked")
        Request<?, EthCall> request = (Request<?, EthCall>) mock(Request.class);
        doReturn(request).when(web3j).ethCall(any(), eq(DefaultBlockParameterName.LATEST));
        when(request.send()).thenReturn(response);

        ReservationFinalizationOnChainClient.FinalizationStatus status =
            client.readStatus(BigInteger.valueOf(7));

        assertThat(status.activeReservationCount()).isEqualTo(BigInteger.valueOf(3));
        assertThat(status.payoutHeapLength()).isEqualTo(BigInteger.valueOf(8));
        assertThat(status.payoutHeapInvalidCount()).isEqualTo(BigInteger.valueOf(2));
        assertThat(status.oldestPayoutCandidateEnd()).isEqualTo(BigInteger.valueOf(1234));
        assertThat(status.lastFinalizationAt()).isEqualTo(BigInteger.valueOf(1200));
    }

    @Test
    void prepareSignsAndBumpsTheGasPriceForTheSameNonce() throws Exception {
        EthChainId response = new EthChainId();
        response.setResult("0xaa36a7");
        @SuppressWarnings("unchecked")
        Request<?, EthChainId> request = (Request<?, EthChainId>) mock(Request.class);
        doReturn(request).when(web3j).ethChainId();
        when(request.send()).thenReturn(response);

        InstitutionalWalletTransactionDispatcher.PreparedTransaction prepared = client.prepare(
            BigInteger.valueOf(7),
            BigInteger.TEN,
            BigInteger.valueOf(4),
            2,
            BigInteger.valueOf(3_000_000_000L)
        );

        assertThat(prepared.rawTransaction()).startsWith("0x");
        assertThat(prepared.gasPrice()).isEqualTo(BigInteger.valueOf(3_900_000_000L));
    }

    @Test
    void rejectsInvalidBatchAndLabIdsBeforeRpcCalls() {
        assertThatThrownBy(() -> client.encodedCall(BigInteger.ZERO, BigInteger.ONE))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("labId is invalid");
        assertThatThrownBy(() -> client.encodedCall(BigInteger.ONE, BigInteger.valueOf(11)))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("maxBatch must be between 1 and 10");
    }

    @Test
    void preflightUsesTheSameGasLimitAsTheSignedTransaction() throws Exception {
        EthCall response = new EthCall();
        response.setResult("0x");
        @SuppressWarnings("unchecked")
        Request<?, EthCall> request = (Request<?, EthCall>) mock(Request.class);
        var transaction = org.mockito.ArgumentCaptor.forClass(org.web3j.protocol.core.methods.request.Transaction.class);
        doReturn(request).when(web3j).ethCall(transaction.capture(), eq(DefaultBlockParameterName.LATEST));
        when(request.send()).thenReturn(response);

        client.validatePreflight(BigInteger.valueOf(7), BigInteger.TEN);

        assertThat(Numeric.decodeQuantity(transaction.getValue().getGas()))
            .isEqualTo(BigInteger.valueOf(5_000_000));
    }
}
