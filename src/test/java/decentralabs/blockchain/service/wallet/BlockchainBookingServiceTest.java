package decentralabs.blockchain.service.wallet;

import decentralabs.blockchain.contract.Diamond;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.ContractGasProvider;

import java.math.BigInteger;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BlockchainBookingServiceTest {

    @Mock
    private WalletService walletService;

    @Mock
    private Web3j web3j;

    @Mock
    private Diamond diamond;

    private BlockchainBookingService service;

    private static final String TEST_WALLET = "0x1234567890abcdef1234567890abcdef12345678";
    private static final String TEST_CONTRACT_ADDRESS = "0xContractAddress";
    private static final String TEST_RESERVATION_KEY = "0x1111111111111111111111111111111111111111111111111111111111111111";
    private static final BigInteger TEST_LAB_ID = BigInteger.valueOf(42);

    @BeforeEach
    void setUp() {
        service = new BlockchainBookingService(walletService);
        ReflectionTestUtils.setField(service, "contractAddress", TEST_CONTRACT_ADDRESS);

        lenient().when(walletService.getWeb3jInstance()).thenReturn(web3j);
    }

    @Test
    void shouldThrowWhenNeitherReservationKeyNorLabIdProvided() {
        assertThatThrownBy(() -> service.getBookingInfo(TEST_WALLET, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Must provide either 'reservationKey'")
                .hasMessageContaining("or 'labId'");
    }

    @Test
    void shouldRetrieveBookingInfoByReservationKey() throws Exception {
        // Setup mock reservation
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                TEST_WALLET,
                BigInteger.valueOf(1000),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.ONE // CONFIRMED
        );

        // Setup mock lab
        Diamond.Lab lab = createMockLab(
                "https://lab.url",
                "accessKey123",
                "https://metadata.url",
                BigInteger.valueOf(1000)
        );

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(
                    anyString(),
                    any(Web3j.class),
                    any(ReadonlyTransactionManager.class),
                    any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));
            when(diamond.getLab(TEST_LAB_ID)).thenReturn(mockRemoteCall(lab));

            Map<String, Object> result = service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null);

            assertThat(result).isNotNull();
            assertThat(result.get("lab")).isEqualTo(TEST_LAB_ID);
            assertThat(result.get("reservationKey")).isEqualTo(TEST_RESERVATION_KEY);
            assertThat(result.get("price")).isEqualTo(BigInteger.valueOf(1000));
            assertThat(result.get("aud")).isEqualTo("https://lab.url");
            assertThat(result.get("sub")).isEqualTo("accessKey123");
        }
    }

    @Test
    void shouldRejectReservationOwnedByDifferentWallet() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                "0xDifferentWallet000000000000000000000000",
                BigInteger.valueOf(1000),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.ONE
        );

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));

            assertThatThrownBy(() -> service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("does not belong to this wallet");
        }
    }

    @Test
    void shouldRejectReservationWithInvalidStatus() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                TEST_WALLET,
                BigInteger.valueOf(1000),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.valueOf(5) // CANCELLED
        );

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));

            assertThatThrownBy(() -> service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not active");
        }
    }

    @Test
    void shouldRejectExpiredReservation() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                TEST_WALLET,
                BigInteger.valueOf(1000),
                getCurrentTimestamp().subtract(BigInteger.valueOf(7200)),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)), // Ended 1 hour ago
                BigInteger.ONE
        );

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));

            assertThatThrownBy(() -> service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("expired");
        }
    }

    @Test
    void shouldRejectReservationNotYetStarted() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                TEST_WALLET,
                BigInteger.valueOf(1000),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)), // Starts in 1 hour
                getCurrentTimestamp().add(BigInteger.valueOf(7200)),
                BigInteger.ONE
        );

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));

            assertThatThrownBy(() -> service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not started yet");
        }
    }

    @Test
    void shouldAcceptReservationWithInUseStatus() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                TEST_WALLET,
                BigInteger.valueOf(1000),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.valueOf(2) // IN_USE
        );

        Diamond.Lab lab = createMockLab(
                "https://lab.url",
                "accessKey123",
                "https://metadata.url",
                BigInteger.valueOf(1000)
        );

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));
            when(diamond.getLab(TEST_LAB_ID)).thenReturn(mockRemoteCall(lab));

            Map<String, Object> result = service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null);

            assertThat(result).isNotNull();
            assertThat(result.get("lab")).isEqualTo(TEST_LAB_ID);
        }
    }

    @Test
    void shouldRejectReservationWithMismatchedPUC() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                TEST_WALLET,
                BigInteger.valueOf(1000),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.ONE
        );

        // Hash of "user123@uned.es" — the PUC stored on-chain for this reservation
        byte[] pucHash = org.web3j.crypto.Hash.sha3("user123@uned.es".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));
            when(diamond.getReservationPucHash(any(byte[].class))).thenReturn(mockRemoteCall(pucHash));

            assertThatThrownBy(() -> service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null, "different@uned.es"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("does not belong to the provided institutional user");
        }
    }

    // Helper methods

    private BigInteger getCurrentTimestamp() {
        return BigInteger.valueOf(System.currentTimeMillis() / 1000);
    }

    private Diamond.Reservation createMockReservation(
            BigInteger labId, String renter, BigInteger price,
            BigInteger start, BigInteger end, BigInteger status) {
        return new Diamond.Reservation(
                labId,
                renter,
                price,
                "0xLabProvider0000000000000000000000000000",
                status,
                start,
                end,
                BigInteger.ZERO, // requestPeriodStart
                BigInteger.ZERO, // requestPeriodDuration
                "0x0000000000000000000000000000000000000000", // payerInstitution
                "0x0000000000000000000000000000000000000000", // collectorInstitution
                BigInteger.ZERO, // providerShare
                BigInteger.ZERO, // projectTreasuryShare
                BigInteger.ZERO, // subsidiesShare
                BigInteger.ZERO  // governanceShare
        );
    }

    private Diamond.Lab createMockLab(String accessURI, String accessKey, String metadata, BigInteger price) {
        Diamond.LabBase base = new Diamond.LabBase(
                metadata,  // uri
                price,
                accessURI,
                accessKey,
                BigInteger.ZERO
        );
        return new Diamond.Lab(TEST_LAB_ID, base);
    }

    private <T> RemoteFunctionCall<T> mockRemoteCall(T value) throws Exception {
        @SuppressWarnings("unchecked")
        RemoteFunctionCall<T> call = mock(RemoteFunctionCall.class, invocation -> {
            if ("send".equals(invocation.getMethod().getName())) {
                return value;
            }
            return null;
        });
        return call;
    }
}

