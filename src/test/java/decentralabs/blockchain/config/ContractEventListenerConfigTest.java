package decentralabs.blockchain.config;

import decentralabs.blockchain.dto.health.LabMetadata;
import decentralabs.blockchain.notification.ReservationNotificationService;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.intent.IntentPersistenceService;
import decentralabs.blockchain.service.intent.IntentService;
import decentralabs.blockchain.service.persistence.ReservationPersistenceService;
import decentralabs.blockchain.service.wallet.InstitutionalTxManagerProvider;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.service.provider.DistributedReservationAvailabilityLockService;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.Event;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.abi.datatypes.generated.Uint96;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.utils.Numeric;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ContractEventListenerConfigTest {

    @Mock
    private EventPollingFallbackService eventPollingFallbackService;

    @Mock
    private WalletService walletService;

    @Mock
    private LabMetadataService labMetadataService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private DistributedReservationAvailabilityLockService reservationAvailabilityLockService;

    @Mock
    private InstitutionalTxManagerProvider txManagerProvider;

    @Mock
    private ReservationNotificationService reservationNotificationService;

    @Mock
    private ReservationPersistenceService reservationPersistenceService;

    @Mock
    private IntentPersistenceService intentPersistenceService;

    @Mock
    private IntentService intentService;

    @Mock
    private Web3j web3j;

    private ContractEventListenerConfig config;

    @BeforeEach
    void setUp() throws Exception {
        config = new ContractEventListenerConfig(
            eventPollingFallbackService,
            txManagerProvider,
            institutionalWalletService,
            reservationAvailabilityLockService,
            walletService,
            labMetadataService,
            reservationNotificationService,
            reservationPersistenceService,
            intentPersistenceService,
            intentService
        );
        ReflectionTestUtils.setField(config, "diamondContractAddress", "0x1234567890abcdef");
        ReflectionTestUtils.setField(config, "startBlock", "latest");
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        @SuppressWarnings("unchecked")
        Request<?, EthChainId> chainIdRequest = (Request<?, EthChainId>) mock(Request.class);
        EthChainId chainIdResponse = mock(EthChainId.class);
        org.mockito.Mockito.doReturn(chainIdRequest).when(web3j).ethChainId();
        when(chainIdRequest.send()).thenReturn(chainIdResponse);
        when(chainIdResponse.getChainId()).thenReturn(BigInteger.valueOf(11155111));

        org.mockito.Mockito.doAnswer(invocation -> {
            DistributedReservationAvailabilityLockService.LockAction<?> action = invocation.getArgument(1);
            try {
                action.run();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
            return null;
        }).when(reservationAvailabilityLockService).withLock(any(), any());
    }

    @Test
    void shouldConfigureEventListenersForSupportedEvents() {
        ReflectionTestUtils.setField(config, "eventsToListen", "ReservationRequested,ReservationConfirmed");
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

        when(walletService.getWeb3jInstance()).thenReturn(web3j);

        config.configureContractEventListeners();

        verify(walletService).getWeb3jInstance();
        verify(eventPollingFallbackService).initialize(web3j, "0x1234567890abcdef");
        verify(eventPollingFallbackService).start();
    }

    @Test
    void shouldSkipConfigurationWhenDisabled() {
        ReflectionTestUtils.setField(config, "eventsToListen", "ReservationRequested");
        ReflectionTestUtils.setField(config, "eventListeningEnabled", false);

        config.configureContractEventListeners();

        verifyNoInteractions(walletService, labMetadataService, eventPollingFallbackService);
    }

    @Test
    void shouldFilterUnsupportedEventsDuringParsing() {
        ReflectionTestUtils.setField(config, "eventsToListen", "ReservationRequested, UnknownEvent ,ReservationConfirmed");

        List<String> events = ReflectionTestUtils.invokeMethod(config, "parseConfiguredEvents");

        assertThat(events).containsExactly("ReservationRequested", "ReservationConfirmed");
    }

    @Test
    void shouldRejectReservationKeysWithWrongLength() {
        assertThatThrownBy(() ->
            ReflectionTestUtils.invokeMethod(config, "reservationKeyToBytes", "0x1234")
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void classifiesAutomaticDenialsWithoutCollapsingIntoManualDecision() {
        assertThat((BigInteger) ReflectionTestUtils.invokeMethod(
            config,
            "classifyAutomaticDenialReason",
            new IllegalStateException("Unable to load lab metadata")
        )).isEqualTo(BigInteger.valueOf(7));

        assertThat((BigInteger) ReflectionTestUtils.invokeMethod(
            config,
            "classifyAutomaticDenialReason",
            new IllegalArgumentException("Reservation time outside available hours")
        )).isEqualTo(BigInteger.valueOf(2));

        assertThat((BigInteger) ReflectionTestUtils.invokeMethod(
            config,
            "classifyAutomaticDenialReason",
                new RuntimeException("RPC response could not be decoded")
        )).isEqualTo(BigInteger.valueOf(6));
    }

    @Test
    void separatesPolicyRejectionsFromInfrastructureAndRpcFailures() {
        var policy = ReflectionTestUtils.invokeMethod(
            config,
            "classifyReservationProcessingFailure",
            new IllegalArgumentException("Reservation time outside available hours")
        );
        var infrastructure = ReflectionTestUtils.invokeMethod(
            config,
            "classifyReservationProcessingFailure",
            new IllegalStateException("Unable to load lab metadata")
        );

        assertThat(((ReservationProcessingFailure) policy).type())
            .isEqualTo(ReservationProcessingFailure.Type.POLICY_REJECTION);
        assertThat(((ReservationProcessingFailure) infrastructure).type())
            .isEqualTo(ReservationProcessingFailure.Type.INFRASTRUCTURE_UNAVAILABLE);

        var rpc = ReflectionTestUtils.invokeMethod(
            config,
            "classifyReservationProcessingFailure",
            new IllegalStateException("Unable to read overlapping reservations for lab 16")
        );
        assertThat(((ReservationProcessingFailure) rpc).type())
            .isEqualTo(ReservationProcessingFailure.Type.TRANSIENT_RPC_FAILURE);

        var wrappedPolicy = ReflectionTestUtils.invokeMethod(
            config,
            "classifyReservationProcessingFailure",
            new RuntimeException(new IllegalArgumentException("Reservation time outside available hours"))
        );
        assertThat(((ReservationProcessingFailure) wrappedPolicy).type())
            .isEqualTo(ReservationProcessingFailure.Type.POLICY_REJECTION);
    }

    @Test
    void shouldPersistRequestedReservationUsingIndexedKey() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(42),
            "0x00000000000000000000000000000000000000ab",
            BigInteger.ONE,
            "0x00000000000000000000000000000000000000cd",
            BigInteger.ONE,
            BigInteger.valueOf(1000),
            BigInteger.valueOf(2000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000",
            BigInteger.TEN
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        stubReservationPucHash(diamond, "0x" + "00".repeat(32));
        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("ReservationRequested");
        String signature = EventEncoder.encode(eventDefinition);
        String renterTopic = encodeAddressTopic("0x00000000000000000000000000000000000000ab");
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(42));
        String reservationKey = "0x" + "11".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String data = "0x"
            + encodeUintData(BigInteger.valueOf(1000))
            + encodeUintData(BigInteger.valueOf(2000));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, renterTopic, labIdTopic, "0x" + reservationKeyTopic));
        eventLog.setData(data);
        eventLog.setTransactionHash("0xdeadbeef");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationRequested", eventDefinition, eventLog);

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> renterCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> labIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(reservationPersistenceService).upsertReservation(
            keyCaptor.capture(),
            renterCaptor.capture(),
            labIdCaptor.capture(),
            any(),
            any(),
            eq("PENDING")
        );

        assertThat(keyCaptor.getValue()).isEqualTo("0x" + reservationKeyTopic);
        assertThat(renterCaptor.getValue()).isEqualTo("0x00000000000000000000000000000000000000ab");
        assertThat(labIdCaptor.getValue()).isEqualTo("42");
    }

    @Test
    void shouldPropagateEssentialLifecyclePersistenceFailureToJournal() {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);
        org.mockito.Mockito.doThrow(new IllegalStateException("database unavailable"))
            .when(reservationPersistenceService)
            .upsertReservation(any(), any(), any(), any(), any(), eq("PENDING"));

        Log eventLog = buildReservationRequestedLog(
            BigInteger.valueOf(42), "0x" + "11".repeat(32), "0xessential-persistence"
        );

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(
            config,
            "handleContractEvent",
            "ReservationRequested",
            getSupportedEvents().get("ReservationRequested"),
            eventLog
        )).hasMessage("database unavailable");
    }

    @Test
    void shouldPropagateEssentialDecisionFailureToJournal() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);
        ReflectionTestUtils.setField(config, "providerFeaturesEnabled", true);
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x00000000000000000000000000000000000000ee");

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(reservationCall.send()).thenReturn(new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(42),
            "0x00000000000000000000000000000000000000cc",
            BigInteger.ONE,
            "0x00000000000000000000000000000000000000dd",
            BigInteger.ZERO,
            BigInteger.valueOf(1000),
            BigInteger.valueOf(2000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            "0x00000000000000000000000000000000000000cc",
            "0x00000000000000000000000000000000000000dd",
            BigInteger.ZERO
        ));
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        stubReservationPucHash(diamond, "0x" + "13".repeat(32));
        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);
        when(diamond.ownerOf(any(BigInteger.class)))
            .thenThrow(new IllegalStateException("rpc unavailable"));

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(
            config,
            "handleContractEvent",
            "ReservationRequested",
            getSupportedEvents().get("ReservationRequested"),
            buildReservationRequestedLog(BigInteger.valueOf(42), "0x" + "12".repeat(32), "0xessential-decision")
        )).hasRootCauseMessage("rpc unavailable");
    }

    @Test
    void shouldPersistConfirmedReservationLifecycle() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(7),
            "0x00000000000000000000000000000000000000ef",
            BigInteger.ONE,
            "0x00000000000000000000000000000000000000ab",
            BigInteger.ONE,
            BigInteger.valueOf(10),
            BigInteger.valueOf(20),
            BigInteger.ZERO,
            BigInteger.ZERO,
            "0x0",
            "0x0",
            BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        stubReservationPucHash(diamond, "0x" + "00".repeat(32));
        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("ReservationConfirmed");
        String signature = EventEncoder.encode(eventDefinition);
        String reservationKey = "0x" + "22".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(7));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, "0x" + reservationKeyTopic, labIdTopic));
        eventLog.setData("0x");
        eventLog.setTransactionHash("0xbead");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationConfirmed", eventDefinition, eventLog);

        ArgumentCaptor<String> statusCaptor = ArgumentCaptor.forClass(String.class);
        verify(reservationPersistenceService).upsertReservation(
            eq("0x" + reservationKeyTopic),
            eq("0x00000000000000000000000000000000000000ef"),
            eq("7"),
            any(),
            any(),
            statusCaptor.capture()
        );
        assertThat(statusCaptor.getValue()).isEqualTo("CONFIRMED");
    }

    @Test
    void shouldPersistCanceledBooking() {
        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("BookingCanceled");
        String signature = EventEncoder.encode(eventDefinition);

        String reservationKey = "0x" + "33".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(9));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, "0x" + reservationKeyTopic, labIdTopic));
        eventLog.setData("0x");
        eventLog.setTransactionHash("0xca11ce");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "BookingCanceled", eventDefinition, eventLog);

        verify(reservationPersistenceService).upsertReservation(
            eq("0x" + reservationKeyTopic),
            any(),
            eq("9"),
            any(),
            any(),
            eq("CANCELLED")
        );
    }

    @Test
    void shouldPersistProviderCanceledBookingWithFullRefundAuditEvent() {
        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("BookingCanceledByProvider");
        String signature = EventEncoder.encode(eventDefinition);

        String reservationKey = "0x" + "44".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(12));
        String payer = "0x00000000000000000000000000000000000000ab";
        String payerTopic = Numeric.toHexStringNoPrefixZeroPadded(Numeric.toBigInt(payer), 64);
        String data = FunctionEncoder.encodeConstructor(List.of(
            new Address("0x00000000000000000000000000000000000000cd"),
            new Bytes32(new byte[32]),
            new Uint96(BigInteger.valueOf(1234)),
            new Uint8(7)
        ));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, "0x" + reservationKeyTopic, labIdTopic, "0x" + payerTopic));
        eventLog.setData(data);
        eventLog.setTransactionHash("0xprovider-cancel");

        ReflectionTestUtils.invokeMethod(
            config, "handleContractEvent", "BookingCanceledByProvider", eventDefinition, eventLog
        );

        verify(reservationPersistenceService).upsertReservation(
            eq("0x" + reservationKeyTopic),
            eq(payer),
            eq("12"),
            any(),
            any(),
            eq("CANCELLED")
        );
    }

    @Test
    void shouldIgnoreUnsupportedNonInstitutionalReservationWhenMetadataIsUnavailable() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(5),
            "0x00000000000000000000000000000000000000aa",
            BigInteger.ZERO,
            "0x00000000000000000000000000000000000000aa",
            BigInteger.ZERO, // PENDING
            BigInteger.valueOf(10),
            BigInteger.valueOf(20),
            BigInteger.ZERO,
            BigInteger.ZERO,
            "0x0",
            "0x0",
            BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);

        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);

        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("ReservationRequested");
        String signature = EventEncoder.encode(eventDefinition);
        String renterTopic = encodeAddressTopic("0x00000000000000000000000000000000000000aa");
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(5));
        String reservationKey = "0x" + "44".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String data = "0x"
            + encodeUintData(BigInteger.valueOf(10))
            + encodeUintData(BigInteger.valueOf(20));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, renterTopic, labIdTopic, "0x" + reservationKeyTopic));
        eventLog.setData(data);
        eventLog.setTransactionHash("0xdeadfeed");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationRequested", eventDefinition, eventLog);

        verifyNoInteractions(writableDiamond);
    }

    private Map<String, Event> getSupportedEvents() {
        @SuppressWarnings("unchecked")
        Map<String, Event> events =
            (Map<String, Event>) ReflectionTestUtils.getField(ContractEventListenerConfig.class, "SUPPORTED_EVENTS");
        return events;
    }

    private String encodeAddressTopic(String address) {
        return Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(address),
            64
        );
    }

    private String encodeUintTopic(BigInteger value) {
        return Numeric.toHexStringNoPrefixZeroPadded(value, 64);
    }

    private String encodeUintData(BigInteger value) {
        return Numeric.toHexStringNoPrefixZeroPadded(value, 64);
    }

    private void stubReservationPucHash(decentralabs.blockchain.contract.Diamond diamond, String hashHex) throws Exception {
        @SuppressWarnings("unchecked")
        var pucHashCall = (org.web3j.protocol.core.RemoteFunctionCall<byte[]>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(pucHashCall.send()).thenReturn(Numeric.hexStringToByteArray(hashHex));
        when(diamond.getReservationPucHash(any(byte[].class))).thenReturn(pucHashCall);
    }

    @Test
    void shouldPersistReservationCanceledAndSendNotification() {
        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("ReservationRequestCanceled");
        String signature = EventEncoder.encode(eventDefinition);

        String reservationKey = "0x" + "55".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(11));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, "0x" + reservationKeyTopic, labIdTopic));
        eventLog.setData("0x");
        eventLog.setTransactionHash("0xcanceled");
        eventLog.setBlockNumber("0x100");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationRequestCanceled", eventDefinition, eventLog);

        verify(reservationPersistenceService).upsertReservation(
            eq("0x" + reservationKeyTopic),
            any(),
            eq("11"),
            any(),
            any(),
            eq("CANCELLED")
        );

        verify(reservationNotificationService).notifyReservationCancelled(any());
    }

    @Test
    void shouldSendNotificationOnReservationConfirmed() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(8),
            "0x00000000000000000000000000000000000000ff",
            BigInteger.ONE,
            "0x00000000000000000000000000000000000000ab",
            BigInteger.ONE, // CONFIRMED
            BigInteger.valueOf(100),
            BigInteger.valueOf(200),
            BigInteger.ZERO,
            BigInteger.ZERO,
            "0x0",
            "0x0",
            BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        stubReservationPucHash(diamond, "0x" + "00".repeat(32));
        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("ReservationConfirmed");
        String signature = EventEncoder.encode(eventDefinition);
        String reservationKey = "0x" + "66".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(8));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, "0x" + reservationKeyTopic, labIdTopic));
        eventLog.setData("0x");
        eventLog.setTransactionHash("0xconfirmed");
        eventLog.setBlockNumber("0x200");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationConfirmed", eventDefinition, eventLog);

        verify(reservationNotificationService).notifyReservationApproved(any());
        verify(reservationPersistenceService).upsertReservation(
            eq("0x" + reservationKeyTopic),
            any(),
            eq("8"),
            any(),
            any(),
            eq("CONFIRMED")
        );
    }

    @Test
    void shouldIgnoreUnsupportedNonInstitutionalReservation() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(15),
            "0x00000000000000000000000000000000000000bb",
            BigInteger.ZERO, // status = PENDING
            "0x00000000000000000000000000000000000000bb",
            BigInteger.ZERO,
            BigInteger.valueOf(1000),
            BigInteger.valueOf(2000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            "0x0",
            "0x0",
            BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);

        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);

        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("ReservationRequested");
        String signature = EventEncoder.encode(eventDefinition);
        String renterTopic = encodeAddressTopic("0x00000000000000000000000000000000000000bb");
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(15));
        String reservationKey = "0x" + "77".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String data = "0x"
            + encodeUintData(BigInteger.valueOf(1000))
            + encodeUintData(BigInteger.valueOf(2000));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, renterTopic, labIdTopic, "0x" + reservationKeyTopic));
        eventLog.setData(data);
        eventLog.setTransactionHash("0xautoapprove");
        eventLog.setBlockNumber("0x300");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationRequested", eventDefinition, eventLog);

        verifyNoInteractions(writableDiamond);
    }

    @Test
    void shouldIgnoreUnsupportedNonInstitutionalReservationWithoutRaceHandling() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var pendingReservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(17),
            "0x00000000000000000000000000000000000000ee",
            BigInteger.ZERO,
            "0x00000000000000000000000000000000000000ee",
            BigInteger.ZERO,
            BigInteger.valueOf(1000),
            BigInteger.valueOf(2000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            "0x0",
            "0x0",
            BigInteger.ZERO
        );
        var confirmedReservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(17),
            "0x00000000000000000000000000000000000000ee",
            BigInteger.ZERO,
            "0x00000000000000000000000000000000000000ee",
            BigInteger.ONE,
            BigInteger.valueOf(1000),
            BigInteger.valueOf(2000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            "0x0",
            "0x0",
            BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(pendingReservation, confirmedReservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        stubReservationPucHash(diamond, "0x" + "00".repeat(32));

        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);

        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("ReservationRequested");
        String signature = EventEncoder.encode(eventDefinition);
        String renterTopic = encodeAddressTopic("0x00000000000000000000000000000000000000ee");
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(17));
        String reservationKey = "0x" + "99".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String data = "0x"
            + encodeUintData(BigInteger.valueOf(1000))
            + encodeUintData(BigInteger.valueOf(2000));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, renterTopic, labIdTopic, "0x" + reservationKeyTopic));
        eventLog.setData(data);
        eventLog.setTransactionHash("0xrace");
        eventLog.setBlockNumber("0x302");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationRequested", eventDefinition, eventLog);

        verifyNoInteractions(writableDiamond);
    }

    @Test
    void shouldConfirmInstitutionalReservationWithProviderWalletAndStoredPucHash() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);
        ReflectionTestUtils.setField(config, "providerFeaturesEnabled", true);
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x00000000000000000000000000000000000000dd");
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        @SuppressWarnings("unchecked")
        Request<?, EthChainId> chainIdRequest = (Request<?, EthChainId>) mock(Request.class);
        EthChainId chainIdResponse = mock(EthChainId.class);
        org.mockito.Mockito.doReturn(chainIdRequest).when(web3j).ethChainId();
        when(chainIdRequest.send()).thenReturn(chainIdResponse);
        when(chainIdResponse.getChainId()).thenReturn(BigInteger.valueOf(11155111));

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(16),
            "0x00000000000000000000000000000000000000cc",
            BigInteger.ZERO,
            "0x00000000000000000000000000000000000000cc",
            BigInteger.ZERO,
            BigInteger.valueOf(1000),
            BigInteger.valueOf(2000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            "0x00000000000000000000000000000000000000cc",
            "0x00000000000000000000000000000000000000dd",
            BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        String storedPucHash = "0x" + "12".repeat(32);
        stubReservationPucHash(diamond, storedPucHash);

        @SuppressWarnings("unchecked")
        var ownerCall = (org.web3j.protocol.core.RemoteFunctionCall<String>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(ownerCall.send()).thenReturn("0x00000000000000000000000000000000000000dd");
        when(diamond.ownerOf(any(BigInteger.class))).thenReturn(ownerCall);

        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);
        @SuppressWarnings("unchecked")
        var confirmCall = (org.web3j.protocol.core.RemoteFunctionCall<org.web3j.protocol.core.methods.response.TransactionReceipt>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(confirmCall.send()).thenReturn(new org.web3j.protocol.core.methods.response.TransactionReceipt());
        when(writableDiamond.confirmInstitutionalReservationRequestWithPucHash(any(), any(), any())).thenReturn(confirmCall);

        LabMetadata metadata = new LabMetadata();
        metadata.setName("Institutional Test Lab");
        metadata.setMaxConcurrentUsers(2);
        when(labMetadataService.getLabMetadataForLab(eq(BigInteger.valueOf(16))))
            .thenReturn(metadata);
        @SuppressWarnings("unchecked")
        var overlapCall = (org.web3j.protocol.core.RemoteFunctionCall<BigInteger>) mock(
            org.web3j.protocol.core.RemoteFunctionCall.class
        );
        when(overlapCall.send()).thenReturn(BigInteger.ONE);
        when(diamond.getConcurrentReservationCount(eq(BigInteger.valueOf(16)), any(), any())).thenReturn(overlapCall);
        doNothing().when(labMetadataService).validateAvailability(any(), any(), any(), eq(2));

        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("ReservationRequested");
        String signature = EventEncoder.encode(eventDefinition);
        String renterTopic = encodeAddressTopic("0x00000000000000000000000000000000000000cc");
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(16));
        String reservationKey = "0x" + "88".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String data = "0x"
            + encodeUintData(BigInteger.valueOf(1000))
            + encodeUintData(BigInteger.valueOf(2000));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, renterTopic, labIdTopic, "0x" + reservationKeyTopic));
        eventLog.setData(data);
        eventLog.setTransactionHash("0xstoredpuchash");
        eventLog.setBlockNumber("0x301");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationRequested", eventDefinition, eventLog);

        verify(writableDiamond).confirmInstitutionalReservationRequestWithPucHash(
            eq("0x00000000000000000000000000000000000000cc"),
            any(byte[].class),
            eq(storedPucHash)
        );
        verify(diamond).getConcurrentReservationCount(
            eq(BigInteger.valueOf(16)),
            eq(BigInteger.valueOf(1000)),
            eq(BigInteger.valueOf(2000))
        );
        verify(writableDiamond, never()).denyReservationRequest(any(byte[].class));
    }

    @Test
    void shouldNotConfirmCrossInstitutionalReservationWithPayerInstitution() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);
        ReflectionTestUtils.setField(config, "providerFeaturesEnabled", true);
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x00000000000000000000000000000000000000cc");

        String payerInstitution = "0x00000000000000000000000000000000000000cc";
        String providerInstitution = "0x00000000000000000000000000000000000000dd";

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(18),
            payerInstitution,
            BigInteger.valueOf(3600),
            providerInstitution,
            BigInteger.ZERO,
            BigInteger.valueOf(1000),
            BigInteger.valueOf(2000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            payerInstitution,
            providerInstitution,
            BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        String storedPucHash = "0x" + "34".repeat(32);
        stubReservationPucHash(diamond, storedPucHash);

        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);

        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("ReservationRequested");
        String signature = EventEncoder.encode(eventDefinition);
        String renterTopic = encodeAddressTopic(payerInstitution);
        String labIdTopic = encodeUintTopic(BigInteger.valueOf(18));
        String reservationKey = "0x" + "aa".repeat(32);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String data = "0x"
            + encodeUintData(BigInteger.valueOf(1000))
            + encodeUintData(BigInteger.valueOf(2000));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, renterTopic, labIdTopic, "0x" + reservationKeyTopic));
        eventLog.setData(data);
        eventLog.setTransactionHash("0xcrossinstitutional");
        eventLog.setBlockNumber("0x401");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationRequested", eventDefinition, eventLog);

        verify(diamond, never()).getLab(any(BigInteger.class));
        verify(writableDiamond, never()).confirmInstitutionalReservationRequestWithPucHash(any(), any(), any());
        verify(writableDiamond, never()).denyReservationRequest(any(byte[].class));
    }

    @Test
    void shouldKeepConsumerOnlyReservationListenerInformational() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);
        ReflectionTestUtils.setField(config, "providerFeaturesEnabled", false);

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(21),
            "0x00000000000000000000000000000000000000cc",
            BigInteger.ZERO,
            "0x00000000000000000000000000000000000000dd",
            BigInteger.ZERO,
            BigInteger.valueOf(1000),
            BigInteger.valueOf(2000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            "0x00000000000000000000000000000000000000cc",
            "0x00000000000000000000000000000000000000dd",
            BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        stubReservationPucHash(diamond, "0x" + "57".repeat(32));
        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);

        ReflectionTestUtils.invokeMethod(
            config,
            "handleContractEvent",
            "ReservationRequested",
            getSupportedEvents().get("ReservationRequested"),
            buildReservationRequestedLog(BigInteger.valueOf(21), "0x" + "dd".repeat(32), "0xconsumer-only")
        );

        verify(institutionalWalletService, never()).getInstitutionalWalletAddress();
        verify(diamond, never()).ownerOf(any(BigInteger.class));
        verify(diamond, never()).getLab(any(BigInteger.class));
        verifyNoInteractions(labMetadataService, writableDiamond);
    }

    @Test
    void shouldNotRunReservationReconciliationWhenProviderAutomationIsDisabled() {
        ReflectionTestUtils.setField(config, "reservationReconcileEnabled", true);
        ReflectionTestUtils.setField(config, "providerFeaturesEnabled", false);

        config.reconcilePendingReservations();

        verifyNoInteractions(reservationPersistenceService, intentPersistenceService);
    }

    @Test
    void shouldSkipReservationProcessingWhenLocalWalletHasNoOnChainRole() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);
        ReflectionTestUtils.setField(config, "providerFeaturesEnabled", true);
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x00000000000000000000000000000000000000ee");

        String payerInstitution = "0x00000000000000000000000000000000000000cc";
        String providerInstitution = "0x00000000000000000000000000000000000000dd";
        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);

        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(19),
            payerInstitution,
            BigInteger.valueOf(3600),
            providerInstitution,
            BigInteger.ZERO,
            BigInteger.valueOf(1000),
            BigInteger.valueOf(2000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            payerInstitution,
            providerInstitution,
            BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        stubReservationPucHash(diamond, "0x" + "45".repeat(32));

        @SuppressWarnings("unchecked")
        var ownerCall = (org.web3j.protocol.core.RemoteFunctionCall<String>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(ownerCall.send()).thenReturn(providerInstitution);
        when(diamond.ownerOf(any(BigInteger.class))).thenReturn(ownerCall);

        @SuppressWarnings("unchecked")
        var providerBackendCall = (org.web3j.protocol.core.RemoteFunctionCall<String>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(providerBackendCall.send()).thenReturn("0x0000000000000000000000000000000000000002");
        when(diamond.getAuthorizedBackend(eq(providerInstitution))).thenReturn(providerBackendCall);

        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);
        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);

        Log eventLog = buildReservationRequestedLog(BigInteger.valueOf(19), "0x" + "bb".repeat(32), "0xunrelated");
        Event eventDefinition = getSupportedEvents().get("ReservationRequested");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationRequested", eventDefinition, eventLog);

        verify(diamond, never()).getLab(any(BigInteger.class));
        verifyNoInteractions(labMetadataService, writableDiamond);
    }

    @Test
    void shouldAllowProviderBackendToAutoConfirmWhenProviderAutomationIsEnabled() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);
        ReflectionTestUtils.setField(config, "providerFeaturesEnabled", true);

        String payerInstitution = "0x00000000000000000000000000000000000000cc";
        String providerInstitution = "0x00000000000000000000000000000000000000dd";
        String providerBackend = "0x00000000000000000000000000000000000000bb";
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(providerBackend);

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(20),
            payerInstitution,
            BigInteger.valueOf(3600),
            providerInstitution,
            BigInteger.ZERO,
            BigInteger.valueOf(1000),
            BigInteger.valueOf(2000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            payerInstitution,
            providerInstitution,
            BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        stubReservationPucHash(diamond, "0x" + "56".repeat(32));

        @SuppressWarnings("unchecked")
        var ownerCall = (org.web3j.protocol.core.RemoteFunctionCall<String>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(ownerCall.send()).thenReturn(providerInstitution);
        when(diamond.ownerOf(any(BigInteger.class))).thenReturn(ownerCall);

        @SuppressWarnings("unchecked")
        var providerBackendCall = (org.web3j.protocol.core.RemoteFunctionCall<String>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(providerBackendCall.send()).thenReturn(providerBackend);
        when(diamond.getAuthorizedBackend(eq(providerInstitution))).thenReturn(providerBackendCall);

        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);
        @SuppressWarnings("unchecked")
        var confirmCall = (org.web3j.protocol.core.RemoteFunctionCall<org.web3j.protocol.core.methods.response.TransactionReceipt>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(confirmCall.send()).thenReturn(new org.web3j.protocol.core.methods.response.TransactionReceipt());
        when(writableDiamond.confirmInstitutionalReservationRequestWithPucHash(any(), any(), any())).thenReturn(confirmCall);

        LabMetadata metadata = new LabMetadata();
        metadata.setName("Provider Lab");
        when(labMetadataService.getLabMetadataForLab(eq(BigInteger.valueOf(20))))
            .thenReturn(metadata);
        doNothing().when(labMetadataService).validateAvailability(any(), any(), any(), anyInt());

        Log eventLog = buildReservationRequestedLog(BigInteger.valueOf(20), "0x" + "cc".repeat(32), "0xprovider-backend");
        Event eventDefinition = getSupportedEvents().get("ReservationRequested");

        ReflectionTestUtils.invokeMethod(config, "handleContractEvent", "ReservationRequested", eventDefinition, eventLog);

        verify(writableDiamond).confirmInstitutionalReservationRequestWithPucHash(
            eq(payerInstitution),
            any(byte[].class),
            eq("0x" + "56".repeat(32))
        );
    }

    private Log buildReservationRequestedLog(BigInteger labId, String reservationKey, String transactionHash) {
        Event eventDefinition = getSupportedEvents().get("ReservationRequested");
        String signature = EventEncoder.encode(eventDefinition);
        String renterTopic = encodeAddressTopic("0x00000000000000000000000000000000000000cc");
        String labIdTopic = encodeUintTopic(labId);
        String reservationKeyTopic = Numeric.toHexStringNoPrefixZeroPadded(
            Numeric.toBigInt(reservationKey), 64
        );
        String data = "0x"
            + encodeUintData(BigInteger.valueOf(1000))
            + encodeUintData(BigInteger.valueOf(2000));

        Log eventLog = new Log();
        eventLog.setTopics(List.of(signature, renterTopic, labIdTopic, "0x" + reservationKeyTopic));
        eventLog.setData(data);
        eventLog.setTransactionHash(transactionHash);
        eventLog.setBlockNumber("0x500");
        return eventLog;
    }
}
