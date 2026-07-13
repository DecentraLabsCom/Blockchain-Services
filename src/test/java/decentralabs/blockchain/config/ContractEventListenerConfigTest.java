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
import org.web3j.abi.datatypes.Event;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.utils.Numeric;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
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
    void setUp() {
        config = new ContractEventListenerConfig(
            eventPollingFallbackService,
            txManagerProvider,
            institutionalWalletService,
            walletService,
            labMetadataService,
            reservationNotificationService,
            reservationPersistenceService,
            intentPersistenceService,
            intentService
        );
        ReflectionTestUtils.setField(config, "diamondContractAddress", "0x1234567890abcdef");
        ReflectionTestUtils.setField(config, "startBlock", "latest");
        lenient().when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x1111111111111111111111111111111111111111");
        lenient().when(walletService.isLabOwnedByProvider(anyString(), any(BigInteger.class)))
            .thenReturn(true);
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
    void shouldKeepReservationPendingWhenMetadataIsTemporarilyUnavailable() throws Exception {
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

        @SuppressWarnings("unchecked")
        var labCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Lab>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        decentralabs.blockchain.contract.Diamond.LabBase base =
            new decentralabs.blockchain.contract.Diamond.LabBase(
                "ipfs://lab-metadata", BigInteger.ZERO, "", "", BigInteger.ZERO
            );
        decentralabs.blockchain.contract.Diamond.Lab lab =
            new decentralabs.blockchain.contract.Diamond.Lab(BigInteger.valueOf(5), base);
        when(labCall.send()).thenReturn(lab);
        when(diamond.getLab(any(BigInteger.class))).thenReturn(labCall);

        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);

        when(labMetadataService.getLabMetadata("ipfs://lab-metadata"))
            .thenThrow(new IllegalStateException("metadata not found"));

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

        verify(writableDiamond, never()).denyReservationRequest(any(byte[].class));
    }

    @Test
    void shouldClassifyAvailabilityViolationsAsPolicyOrCapacityDenials() {
        Object policy = ReflectionTestUtils.invokeMethod(
            config,
            "classifyReservationFailure",
            "AVAILABILITY",
            new IllegalArgumentException("Lab not available on SUNDAY")
        );
        Object capacity = ReflectionTestUtils.invokeMethod(
            config,
            "classifyReservationFailure",
            "AVAILABILITY",
            new IllegalArgumentException("Too many concurrent users requested")
        );

        assertThat(policy.toString()).isEqualTo("POLICY_DENIED");
        assertThat(capacity.toString()).isEqualTo("CAPACITY_DENIED");
    }

    @Test
    void shouldClassifyMetadataAndRpcFailuresAsTransient() {
        Object metadata = ReflectionTestUtils.invokeMethod(
            config,
            "classifyReservationFailure",
            "METADATA",
            new IllegalStateException("timeout")
        );
        Object rpc = ReflectionTestUtils.invokeMethod(
            config,
            "classifyReservationFailure",
            "RPC",
            new IllegalStateException("connection reset")
        );

        assertThat(metadata.toString()).isEqualTo("TRANSIENT_METADATA_ERROR");
        assertThat(rpc.toString()).isEqualTo("TRANSIENT_RPC_ERROR");
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
    void shouldAutoApproveReservationWhenValidateAvailabilityPasses() throws Exception {
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

        @SuppressWarnings("unchecked")
        var labCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Lab>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        decentralabs.blockchain.contract.Diamond.LabBase base =
            new decentralabs.blockchain.contract.Diamond.LabBase(
                "ipfs://auto-lab-metadata", BigInteger.ZERO, "", "", BigInteger.ZERO
            );
        decentralabs.blockchain.contract.Diamond.Lab lab =
            new decentralabs.blockchain.contract.Diamond.Lab(BigInteger.valueOf(15), base);
        when(labCall.send()).thenReturn(lab);
        when(diamond.getLab(any(BigInteger.class))).thenReturn(labCall);

        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var confirmCall = (org.web3j.protocol.core.RemoteFunctionCall<org.web3j.protocol.core.methods.response.TransactionReceipt>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(confirmCall.send()).thenReturn(new org.web3j.protocol.core.methods.response.TransactionReceipt());
        when(writableDiamond.confirmReservationRequest(any(byte[].class))).thenReturn(confirmCall);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);

        LabMetadata metadata = new LabMetadata();
        metadata.setName("Auto Test Lab");
        when(labMetadataService.getLabMetadata("ipfs://auto-lab-metadata")).thenReturn(metadata);
        doNothing().when(labMetadataService).validateAvailability(any(), any(), any(), anyInt());

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

        verify(writableDiamond).confirmReservationRequest(any(byte[].class));
        verify(writableDiamond, never()).denyReservationRequest(any(byte[].class));
    }

    @Test
    void shouldNotProcessReservationOwnedByAnotherInstitution() {
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x1111111111111111111111111111111111111111");
        when(walletService.isLabOwnedByProvider(
            "0x1111111111111111111111111111111111111111",
            BigInteger.valueOf(42)
        )).thenReturn(false);

        Boolean localOwner = ReflectionTestUtils.invokeMethod(
            config,
            "isLocalLabOwner",
            BigInteger.valueOf(42)
        );

        assertThat(localOwner).isFalse();
    }

    @Test
    void shouldProcessReservationOwnedByLocalInstitution() {
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x1111111111111111111111111111111111111111");
        when(walletService.isLabOwnedByProvider(
            "0x1111111111111111111111111111111111111111",
            BigInteger.valueOf(42)
        )).thenReturn(true);

        Boolean localOwner = ReflectionTestUtils.invokeMethod(
            config,
            "isLocalLabOwner",
            BigInteger.valueOf(42)
        );

        assertThat(localOwner).isTrue();
    }

    @Test
    void shouldSkipAutoDenyWhenReservationWasConfirmedConcurrently() throws Exception {
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

        @SuppressWarnings("unchecked")
        var labCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Lab>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        decentralabs.blockchain.contract.Diamond.LabBase base =
            new decentralabs.blockchain.contract.Diamond.LabBase(
                "ipfs://race-lab-metadata", BigInteger.ZERO, "", "", BigInteger.ZERO
            );
        decentralabs.blockchain.contract.Diamond.Lab lab =
            new decentralabs.blockchain.contract.Diamond.Lab(BigInteger.valueOf(17), base);
        when(labCall.send()).thenReturn(lab);
        when(diamond.getLab(any(BigInteger.class))).thenReturn(labCall);
        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var confirmCall = (org.web3j.protocol.core.RemoteFunctionCall<org.web3j.protocol.core.methods.response.TransactionReceipt>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(confirmCall.send()).thenThrow(new RuntimeException("execution reverted: Not pending"));
        when(writableDiamond.confirmReservationRequest(any(byte[].class))).thenReturn(confirmCall);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);

        LabMetadata metadata = new LabMetadata();
        metadata.setName("Race Test Lab");
        when(labMetadataService.getLabMetadata("ipfs://race-lab-metadata")).thenReturn(metadata);
        doNothing().when(labMetadataService).validateAvailability(any(), any(), any(), anyInt());

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

        verify(writableDiamond).confirmReservationRequest(any(byte[].class));
        verify(writableDiamond, never()).denyReservationRequest(any(byte[].class));
    }

    @Test
    void shouldConfirmInstitutionalReservationWithStoredPucHash() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

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
        var labCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Lab>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        decentralabs.blockchain.contract.Diamond.LabBase base =
            new decentralabs.blockchain.contract.Diamond.LabBase(
                "ipfs://institutional-lab-metadata", BigInteger.ZERO, "", "", BigInteger.ZERO
            );
        decentralabs.blockchain.contract.Diamond.Lab lab =
            new decentralabs.blockchain.contract.Diamond.Lab(BigInteger.valueOf(16), base);
        when(labCall.send()).thenReturn(lab);
        when(diamond.getLab(any(BigInteger.class))).thenReturn(labCall);

        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);
        @SuppressWarnings("unchecked")
        var confirmCall = (org.web3j.protocol.core.RemoteFunctionCall<org.web3j.protocol.core.methods.response.TransactionReceipt>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(confirmCall.send()).thenReturn(new org.web3j.protocol.core.methods.response.TransactionReceipt());
        when(writableDiamond.confirmInstitutionalReservationRequestWithPucHash(any(), any(), any())).thenReturn(confirmCall);

        LabMetadata metadata = new LabMetadata();
        metadata.setName("Institutional Test Lab");
        when(labMetadataService.getLabMetadata("ipfs://institutional-lab-metadata")).thenReturn(metadata);
        doNothing().when(labMetadataService).validateAvailability(any(), any(), any(), anyInt());

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
        verify(writableDiamond, never()).denyReservationRequest(any(byte[].class));
    }

    @Test
    void shouldConfirmCrossInstitutionalReservationWithPayerInstitution() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

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

        @SuppressWarnings("unchecked")
        var labCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Lab>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        decentralabs.blockchain.contract.Diamond.LabBase base =
            new decentralabs.blockchain.contract.Diamond.LabBase(
                "ipfs://cross-institutional-lab", BigInteger.ONE, "", "", BigInteger.ZERO
            );
        decentralabs.blockchain.contract.Diamond.Lab lab =
            new decentralabs.blockchain.contract.Diamond.Lab(BigInteger.valueOf(18), base);
        when(labCall.send()).thenReturn(lab);
        when(diamond.getLab(any(BigInteger.class))).thenReturn(labCall);
        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);
        @SuppressWarnings("unchecked")
        var confirmCall = (org.web3j.protocol.core.RemoteFunctionCall<org.web3j.protocol.core.methods.response.TransactionReceipt>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(confirmCall.send()).thenReturn(new org.web3j.protocol.core.methods.response.TransactionReceipt());
        when(writableDiamond.confirmInstitutionalReservationRequestWithPucHash(any(), any(), any())).thenReturn(confirmCall);

        LabMetadata metadata = new LabMetadata();
        metadata.setName("Cross Institutional Lab");
        when(labMetadataService.getLabMetadata("ipfs://cross-institutional-lab")).thenReturn(metadata);
        doNothing().when(labMetadataService).validateAvailability(any(), any(), any(), anyInt());

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

        verify(writableDiamond).confirmInstitutionalReservationRequestWithPucHash(
            eq(payerInstitution),
            any(byte[].class),
            eq(storedPucHash)
        );
        verify(writableDiamond, never()).denyReservationRequest(any(byte[].class));
    }

    @Test
    void shouldFinalizeExpiredInstitutionalRequestOnChainWithoutLoadingMetadata() throws Exception {
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);
        String institution = "0x00000000000000000000000000000000000000cc";
        BigInteger now = BigInteger.valueOf(java.time.Instant.now().getEpochSecond());

        var diamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var reservationCall = (org.web3j.protocol.core.RemoteFunctionCall<decentralabs.blockchain.contract.Diamond.Reservation>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        var reservation = new decentralabs.blockchain.contract.Diamond.Reservation(
            BigInteger.valueOf(19), institution, BigInteger.valueOf(50), institution,
            BigInteger.ZERO, now.add(BigInteger.valueOf(300)), now.add(BigInteger.valueOf(600)),
            now.subtract(BigInteger.valueOf(120)), BigInteger.TEN,
            institution, institution, BigInteger.ZERO
        );
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getReservation(any(byte[].class))).thenReturn(reservationCall);
        String pucHash = "0x" + "56".repeat(32);
        stubReservationPucHash(diamond, pucHash);
        ReflectionTestUtils.setField(config, "cachedDiamond", diamond);

        var writableDiamond = mock(decentralabs.blockchain.contract.Diamond.class);
        @SuppressWarnings("unchecked")
        var confirmCall = (org.web3j.protocol.core.RemoteFunctionCall<org.web3j.protocol.core.methods.response.TransactionReceipt>) mock(org.web3j.protocol.core.RemoteFunctionCall.class);
        when(confirmCall.send()).thenReturn(new org.web3j.protocol.core.methods.response.TransactionReceipt());
        when(writableDiamond.confirmInstitutionalReservationRequestWithPucHash(any(), any(), any()))
            .thenReturn(confirmCall);
        ReflectionTestUtils.setField(config, "writableDiamond", writableDiamond);

        Map<String, Event> supported = getSupportedEvents();
        Event eventDefinition = supported.get("ReservationRequested");
        String reservationKey = "0x" + "bb".repeat(32);
        Log eventLog = new Log();
        eventLog.setTopics(List.of(
            EventEncoder.encode(eventDefinition),
            encodeAddressTopic(institution),
            encodeUintTopic(BigInteger.valueOf(19)),
            reservationKey
        ));
        eventLog.setData("0x" + encodeUintData(reservation.start) + encodeUintData(reservation.end));
        eventLog.setTransactionHash("0xexpiredinstitutional");

        ReflectionTestUtils.invokeMethod(
            config, "handleContractEvent", "ReservationRequested", eventDefinition, eventLog
        );

        verify(writableDiamond).confirmInstitutionalReservationRequestWithPucHash(
            eq(institution), any(byte[].class), eq(pucHash)
        );
        verifyNoInteractions(labMetadataService);
    }
}
