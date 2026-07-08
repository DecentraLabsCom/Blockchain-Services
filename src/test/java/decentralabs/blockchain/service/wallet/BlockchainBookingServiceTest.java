package decentralabs.blockchain.service.wallet;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.service.guacamole.GuacamoleProvisioningService;
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

    @Mock
    private GuacamoleProvisioningService guacamoleProvisioningService;

    private BlockchainBookingService service;

    private static final String TEST_WALLET = "0x1234567890abcdef1234567890abcdef12345678";
    private static final String TEST_CONTRACT_ADDRESS = "0xContractAddress";
    private static final String TEST_RESERVATION_KEY = "0x1111111111111111111111111111111111111111111111111111111111111111";
    private static final BigInteger TEST_LAB_ID = BigInteger.valueOf(42);

    @BeforeEach
    void setUp() {
        service = new BlockchainBookingService(walletService, guacamoleProvisioningService);
        ReflectionTestUtils.setField(service, "contractAddress", TEST_CONTRACT_ADDRESS);
        ReflectionTestUtils.setField(service, "labAccessJwtMaxTtlSeconds", 14_400L);

        lenient().when(walletService.getWeb3jInstance()).thenReturn(web3j);
        lenient().when(guacamoleProvisioningService.provisionTemporaryUser(anyString(), anyString(), any(), anyString()))
                .thenAnswer(invocation -> {
                    String selector = invocation.getArgument(0);
                    String sessionId = invocation.getArgument(1);
                    long connectionId = GuacamoleProvisioningService.parseConnectionId(selector);
                    return new GuacamoleProvisioningService.ProvisioningResult(
                            sessionId,
                            "dlabs-res-" + sessionId,
                            new GuacamoleProvisioningService.ConnectionMetadata(
                                    connectionId,
                                    selector,
                                    "RDP Lab",
                                    "rdp",
                                    "lab-ws-01",
                                    "3389"
                            )
                    );
                });
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
                "guac:id:123",
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
            assertThat(result.get("reservationStatus")).isEqualTo(BigInteger.ONE);
            assertThat(result.get("price")).isEqualTo(BigInteger.valueOf(1000));
            assertThat(result.get("aud")).isEqualTo("https://lab.url");
            String expectedSessionId = TEST_RESERVATION_KEY.substring(2);
            assertThat(result.get("sub")).isEqualTo("dlabs-res-" + expectedSessionId);
            assertThat(result.get("accessKey")).isEqualTo("guac:id:123");
            assertThat(result.get("guacSessionId")).isEqualTo(expectedSessionId);
            assertThat(result.get("guacamoleConnectionId")).isEqualTo(BigInteger.valueOf(123));
            verify(guacamoleProvisioningService).provisionTemporaryUser(eq("guac:id:123"), eq(expectedSessionId), any(), eq("https://lab.url"));
        }
    }

    @Test
    void shouldRetrieveCheckInBookingInfoWithoutProvisioningGuacamoleAccess() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                TEST_WALLET,
                BigInteger.valueOf(1000),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.ONE
        );

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(
                    anyString(),
                    any(Web3j.class),
                    any(ReadonlyTransactionManager.class),
                    any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));

            Map<String, Object> result = service.getCheckInBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null, null);

            assertThat(result).isNotNull();
            assertThat(result.get("lab")).isEqualTo(TEST_LAB_ID);
            assertThat(result.get("reservationKey")).isEqualTo(TEST_RESERVATION_KEY);
            assertThat(result.get("reservationStatus")).isEqualTo(BigInteger.ONE);
            assertThat(result.get("price")).isEqualTo(BigInteger.valueOf(1000));
            verify(diamond, never()).getLab(any());
            verify(guacamoleProvisioningService, never()).provisionTemporaryUser(anyString(), anyString(), any(), anyString());
        }
    }

    @Test
    void shouldKeepJwtExpirationAtReservationEndWhenReservationIsShorterThanMaxTtl() throws Exception {
        BigInteger now = getCurrentTimestamp();
        BigInteger end = now.add(BigInteger.valueOf(1800));
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                TEST_WALLET,
                BigInteger.valueOf(1000),
                now.subtract(BigInteger.valueOf(300)),
                end,
                BigInteger.ONE
        );
        Diamond.Lab lab = createMockLab(
                "https://lab.url",
                "guac:id:123",
                "https://metadata.url",
                BigInteger.valueOf(1000)
        );

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));
            when(diamond.getLab(TEST_LAB_ID)).thenReturn(mockRemoteCall(lab));

            Map<String, Object> result = service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null);

            assertThat(result.get("exp")).isEqualTo(end);
        }
    }

    @Test
    void shouldCapJwtExpirationForLongReservationsUsingConfiguredMaxTtl() throws Exception {
        BigInteger now = getCurrentTimestamp();
        BigInteger reservationEnd = now.add(BigInteger.valueOf(30L * 24L * 60L * 60L));
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                TEST_WALLET,
                BigInteger.valueOf(1000),
                now.subtract(BigInteger.valueOf(300)),
                reservationEnd,
                BigInteger.ONE
        );
        Diamond.Lab lab = createMockLab(
                "https://lab.url",
                "guac:id:123",
                "https://metadata.url",
                BigInteger.valueOf(1000)
        );

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));
            when(diamond.getLab(TEST_LAB_ID)).thenReturn(mockRemoteCall(lab));

            long before = System.currentTimeMillis() / 1000;
            Map<String, Object> result = service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null);
            long after = System.currentTimeMillis() / 1000;

            assertThat(result.get("exp")).isInstanceOf(BigInteger.class);
            BigInteger exp = (BigInteger) result.get("exp");
            assertThat(exp).isBetween(
                    BigInteger.valueOf(before + 14_400L),
                    BigInteger.valueOf(after + 14_400L)
            );
            assertThat(exp).isLessThan(reservationEnd);
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
    void shouldAcceptReservationWithAccessAuthorizedStatus() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID,
                TEST_WALLET,
                BigInteger.valueOf(1000),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.valueOf(2) // ACCESS_AUTHORIZED
        );

        Diamond.Lab lab = createMockLab(
                "https://lab.url",
                "guac:id:123",
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
            assertThat(result.get("reservationStatus")).isEqualTo(BigInteger.valueOf(2));
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
                BigInteger.ZERO  // providerShare
        );
    }

    private Diamond.Lab createMockLab(String accessURI, String accessKey, String metadata, BigInteger price) {
        return createMockLab(accessURI, accessKey, metadata, price, BigInteger.ZERO);
    }

    private Diamond.Lab createMockLab(String accessURI, String accessKey, String metadata, BigInteger price, BigInteger resourceType) {
        Diamond.LabBase base = new Diamond.LabBase(
                metadata,  // uri
                price,
                accessURI,
                accessKey,
                BigInteger.ZERO,
                resourceType
        );
        return new Diamond.Lab(TEST_LAB_ID, base);
    }

    // ─── FMU resource type tests ─────────────────────────────────────

    @Test
    void shouldSetResourceTypeFmuWhenAccessKeyEndsFmu() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID, TEST_WALLET,
                BigInteger.valueOf(500),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.ONE
        );
        Diamond.Lab lab = createMockLab("https://lab.url", "spring-damper.fmu", "https://meta.url", BigInteger.valueOf(500), BigInteger.ONE);

        try (MockedStatic<Diamond> dm = mockStatic(Diamond.class)) {
            dm.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);
            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));
            when(diamond.getLab(TEST_LAB_ID)).thenReturn(mockRemoteCall(lab));

            Map<String, Object> result = service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null);

            assertThat(result.get("resourceType")).isEqualTo("fmu");
            assertThat(result.get("accessKey")).isEqualTo("spring-damper.fmu");
        }
    }

    @Test
    void shouldSetResourceTypeLabWhenAccessKeyNotFmu() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID, TEST_WALLET,
                BigInteger.valueOf(500),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.ONE
        );
        Diamond.Lab lab = createMockLab("https://lab.url", "guac:id:77", "https://meta.url", BigInteger.valueOf(500));

        try (MockedStatic<Diamond> dm = mockStatic(Diamond.class)) {
            dm.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);
            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));
            when(diamond.getLab(TEST_LAB_ID)).thenReturn(mockRemoteCall(lab));

            Map<String, Object> result = service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null);

            assertThat(result.get("resourceType")).isEqualTo("lab");
            assertThat(result.get("accessKey")).isEqualTo("guac:id:77");
            assertThat(result.get("sub")).asString().startsWith("dlabs-res-");
        }
    }

    @Test
    void shouldSetResourceTypeFmuEvenWhenAccessKeyDoesNotLookLikeFmu() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID, TEST_WALLET,
                BigInteger.valueOf(500),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.ONE
        );
        Diamond.Lab lab = createMockLab("https://lab.url", "guacamole-user", "https://meta.url", BigInteger.valueOf(500), BigInteger.ONE);

        try (MockedStatic<Diamond> dm = mockStatic(Diamond.class)) {
            dm.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);
            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));
            when(diamond.getLab(TEST_LAB_ID)).thenReturn(mockRemoteCall(lab));

            Map<String, Object> result = service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null);

            assertThat(result.get("resourceType")).isEqualTo("fmu");
            assertThat(result.get("accessKey")).isEqualTo("guacamole-user");
        }
    }

    @Test
    void shouldRejectPhysicalLabWithUnprefixedAccessKey() throws Exception {
        Diamond.Reservation reservation = createMockReservation(
                TEST_LAB_ID, TEST_WALLET,
                BigInteger.valueOf(500),
                getCurrentTimestamp().subtract(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                BigInteger.ONE
        );
        Diamond.Lab lab = createMockLab("https://lab.url", "spring-damper.fmu", "https://meta.url", BigInteger.valueOf(500), BigInteger.ZERO);

        try (MockedStatic<Diamond> dm = mockStatic(Diamond.class)) {
            dm.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);
            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(reservation));
            when(diamond.getLab(TEST_LAB_ID)).thenReturn(mockRemoteCall(lab));

            assertThatThrownBy(() -> service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("guac:id");
        }
    }

    @Test
    void shouldApplySameReservationWindowValidationForLabAndFmu() throws Exception {
        Diamond.Reservation futureReservation = createMockReservation(
                TEST_LAB_ID, TEST_WALLET,
                BigInteger.valueOf(500),
                getCurrentTimestamp().add(BigInteger.valueOf(3600)),
                getCurrentTimestamp().add(BigInteger.valueOf(7200)),
                BigInteger.ONE
        );

        try (MockedStatic<Diamond> dm = mockStatic(Diamond.class)) {
            dm.when(() -> Diamond.load(anyString(), any(Web3j.class), any(ReadonlyTransactionManager.class), any(ContractGasProvider.class)))
                    .thenReturn(diamond);

            when(diamond.getReservation(any(byte[].class))).thenReturn(mockRemoteCall(futureReservation));

            assertThatThrownBy(() -> service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not started yet");

            assertThatThrownBy(() -> service.getBookingInfo(TEST_WALLET, TEST_RESERVATION_KEY, null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not started yet");
        }
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

