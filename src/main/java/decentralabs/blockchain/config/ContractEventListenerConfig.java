package decentralabs.blockchain.config;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.health.LabMetadata;
import decentralabs.blockchain.event.NetworkSwitchEvent;
import decentralabs.blockchain.notification.ReservationNotificationData;
import decentralabs.blockchain.notification.ReservationNotificationService;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.persistence.ReservationPersistenceService;
import decentralabs.blockchain.service.intent.IntentService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.EventValues;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Event;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.Contract;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Numeric;

/**
 * Configuration class for setting up contract event listeners on application startup.
 */
@Component
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(value = "features.organizations.enabled", havingValue = "true", matchIfMissing = true)
public class ContractEventListenerConfig {

    private static final String RESERVATION_REQUESTED = "ReservationRequested";
    private static final String RESERVATION_CONFIRMED = "ReservationConfirmed";
    private static final String RESERVATION_DENIED = "ReservationRequestDenied";
    private static final String RESERVATION_CANCELED = "ReservationRequestCanceled";
    private static final String BOOKING_CANCELED = "BookingCanceled";
    private static final String PROVIDER_ADDED = "ProviderAdded";
    private static final String LAB_INTENT_PROCESSED = "LabIntentProcessed";
    private static final String RESERVATION_INTENT_PROCESSED = "ReservationIntentProcessed";

    private final EventPollingFallbackService eventPollingFallbackService;

    private static final Event RESERVATION_REQUESTED_EVENT = new Event(
        RESERVATION_REQUESTED,
        Arrays.<TypeReference<?>>asList(
            new TypeReference<Address>(true) {},
            new TypeReference<Uint256>(true) {},
            new TypeReference<Uint256>() {},
            new TypeReference<Uint256>() {},
            new TypeReference<Bytes32>(true) {}
        )
    );

    private static final Event RESERVATION_CONFIRMED_EVENT = new Event(
        RESERVATION_CONFIRMED,
        Arrays.<TypeReference<?>>asList(
            new TypeReference<Bytes32>(true) {},
            new TypeReference<Uint256>(true) {}
        )
    );

    private static final Event RESERVATION_DENIED_EVENT = new Event(
        RESERVATION_DENIED,
        Arrays.<TypeReference<?>>asList(
            new TypeReference<Bytes32>(true) {},
            new TypeReference<Uint256>(true) {}
        )
    );

    private static final Event RESERVATION_CANCELED_EVENT = new Event(
        RESERVATION_CANCELED,
        Arrays.<TypeReference<?>>asList(
            new TypeReference<Bytes32>(true) {},
            new TypeReference<Uint256>(true) {}
        )
    );

    private static final Event BOOKING_CANCELED_EVENT = new Event(
        BOOKING_CANCELED,
        Arrays.<TypeReference<?>>asList(
            new TypeReference<Bytes32>(true) {},
            new TypeReference<Uint256>(true) {}
        )
    );

    private static final Event PROVIDER_ADDED_EVENT = new Event(
        PROVIDER_ADDED,
        Arrays.<TypeReference<?>>asList(
            new TypeReference<Address>(true) {},
            new TypeReference<Utf8String>() {},
            new TypeReference<Utf8String>() {},
            new TypeReference<Utf8String>() {}
        )
    );

    private static final Event LAB_INTENT_PROCESSED_EVENT = new Event(
        LAB_INTENT_PROCESSED,
        Arrays.<TypeReference<?>>asList(
            new TypeReference<Bytes32>(true) {},
            new TypeReference<Uint256>() {},
            new TypeReference<Utf8String>() {},
            new TypeReference<Address>() {},
            new TypeReference<org.web3j.abi.datatypes.Bool>() {},
            new TypeReference<Utf8String>() {}
        )
    );

    private static final Event RESERVATION_INTENT_PROCESSED_EVENT = new Event(
        RESERVATION_INTENT_PROCESSED,
        Arrays.<TypeReference<?>>asList(
            new TypeReference<Bytes32>(true) {},
            new TypeReference<Bytes32>() {},
            new TypeReference<Utf8String>() {},
            new TypeReference<Utf8String>() {},
            new TypeReference<Address>() {},
            new TypeReference<org.web3j.abi.datatypes.Bool>() {},
            new TypeReference<Utf8String>() {}
        )
    );

    private static final int DEFAULT_RESERVATION_USER_COUNT = 1;
    private static final String ACTION_REQUESTED = "requested";

    private static final Map<String, Event> SUPPORTED_EVENTS = Map.of(
        RESERVATION_REQUESTED, RESERVATION_REQUESTED_EVENT,
        RESERVATION_CONFIRMED, RESERVATION_CONFIRMED_EVENT,
        RESERVATION_DENIED, RESERVATION_DENIED_EVENT,
        RESERVATION_CANCELED, RESERVATION_CANCELED_EVENT,
        BOOKING_CANCELED, BOOKING_CANCELED_EVENT,
        PROVIDER_ADDED, PROVIDER_ADDED_EVENT,
        LAB_INTENT_PROCESSED, LAB_INTENT_PROCESSED_EVENT,
        RESERVATION_INTENT_PROCESSED, RESERVATION_INTENT_PROCESSED_EVENT
    );

    private final WalletService walletService;
    private final LabMetadataService labMetadataService;
    private final InstitutionalWalletService institutionalWalletService;
    private final ReservationNotificationService reservationNotificationService;
    private final ReservationPersistenceService reservationPersistenceService;
    private final IntentService intentService;

    @Value("${contract.address}")
    private String diamondContractAddress;

    private volatile Diamond cachedDiamond;
    private volatile Diamond writableDiamond;

    private final Map<BigInteger, String> labMetadataUriCache = new ConcurrentHashMap<>();

    @Value("${contract.events.to.listen:}")
    private String eventsToListen;

    @Value("${contract.event.listening.enabled:true}")
    private boolean eventListeningEnabled;

    @Value("${contract.event.start.block:latest}")
    private String startBlock;

    @Value("${ethereum.gas.price.default:1}")
    private BigDecimal defaultGasPriceGwei;

    @Value("${ethereum.gas.limit.contract:300000}")
    private BigInteger contractGasLimit;

    /**
     * Configure event listeners for Diamond contract on application startup.
     * Uses EventPollingFallbackService for reliable event capture with both
     * WebSocket subscriptions and HTTP polling fallback.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void configureContractEventListeners() {
        if (!eventListeningEnabled) {
            log.info("Contract event listening is disabled");
            return;
        }

        List<String> configuredEvents = parseConfiguredEvents();
        if (configuredEvents.isEmpty()) {
            log.warn("No valid contract events configured to listen for");
            return;
        }

        log.info("Configuring contract event listeners on startup…");
        log.info("Diamond contract address: {}", diamondContractAddress);
        log.info("Events to listen: {}", configuredEvents);

        try {
            Web3j web3j = walletService.getWeb3jInstance();
            
            // Initialize the polling fallback service
            eventPollingFallbackService.initialize(web3j, diamondContractAddress);
            
            // Register all configured events
            BigInteger startBlockNum = resolveStartBlockNumber();
            for (String eventName : configuredEvents) {
                registerEventWithFallback(eventName, startBlockNum);
            }
            
            // Start the service (WebSocket + polling)
            eventPollingFallbackService.start();
            
            log.info("Contract event listener configuration completed for {} events (with polling fallback)", 
                configuredEvents.size());
        } catch (Exception e) {
            log.error("Error configuring contract event listeners", e);
        }
    }
    
    /**
     * Handles network switch events by reconfiguring all contract event listeners
     */
    @EventListener(NetworkSwitchEvent.class)
    public void onNetworkSwitch(NetworkSwitchEvent event) {
        if (!eventListeningEnabled) {
            return;
        }
        
        log.info("Network switched from {} to {}, reconfiguring contract event listeners...", 
                 event.getOldNetwork(), event.getNewNetwork());
        
        // Clear cached Diamond instances (they're network-specific)
        cachedDiamond = null;
        writableDiamond = null;
        
        // Reset the polling fallback service with new network
        Web3j web3j = walletService.getWeb3jInstance();
        eventPollingFallbackService.resetForNetworkSwitch(web3j, diamondContractAddress);
        
        log.info("Contract event listeners reconfigured for network: {}", event.getNewNetwork());
    }

    /**
     * Register an event with the polling fallback service.
     */
    private void registerEventWithFallback(String eventName, BigInteger startBlock) {
        Event eventDefinition = SUPPORTED_EVENTS.get(eventName);
        if (eventDefinition == null) {
            log.warn("Event '{}' is not supported and will be ignored", eventName);
            return;
        }

        String eventSignature = EventEncoder.encode(eventDefinition);
        log.info("Registering '{}' with signature {} (startBlock={})", eventName, eventSignature, startBlock);

        eventPollingFallbackService.registerEvent(
            eventName,
            eventDefinition,
            startBlock,
            eventLog -> handleLogIfMatches(eventName, eventDefinition, eventSignature, eventLog)
        );
    }

    /**
     * Resolve start block as BigInteger for polling service.
     */
    private BigInteger resolveStartBlockNumber() {
        if (startBlock == null || startBlock.isBlank()) {
            return null; // Will use lookback from current
        }

        String normalized = startBlock.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "earliest" -> BigInteger.ZERO;
            case "latest", "pending" -> null; // Use lookback
            default -> {
                try {
                    yield normalized.startsWith("0x")
                        ? new BigInteger(normalized.substring(2), 16)
                        : new BigInteger(normalized);
                } catch (NumberFormatException ex) {
                    log.warn("Invalid start block '{}', using lookback", startBlock);
                    yield null;
                }
            }
        };
    }

    private List<String> parseConfiguredEvents() {
        if (eventsToListen == null) {
            return List.of();
        }

        List<String> parsed = Arrays.stream(eventsToListen.split(","))
            .map(String::trim)
            .filter(event -> !event.isEmpty())
            .distinct()
            .collect(Collectors.toList());

        if (parsed.isEmpty()) {
            return List.of();
        }

        List<String> unsupported = parsed.stream()
            .filter(event -> !SUPPORTED_EVENTS.containsKey(event))
            .toList();

        if (!unsupported.isEmpty()) {
            log.warn("Skipping unsupported contract events: {}", unsupported);
        }

        return parsed.stream()
            .filter(SUPPORTED_EVENTS::containsKey)
            .toList();
    }

    private void handleLogIfMatches(String eventName, Event eventDefinition, String eventSignature, Log eventLog) {
        List<String> topics = eventLog.getTopics();
        if (topics == null || topics.isEmpty()) {
            log.debug("Ignoring log without topics for tx {}", eventLog.getTransactionHash());
            return;
        }

        if (!eventSignature.equals(topics.get(0))) {
            return;
        }

        handleContractEvent(eventName, eventDefinition, eventLog);
    }

    /**
     * Handle incoming contract events with decoded payloads.
     */
    private void handleContractEvent(String eventName, Event eventDefinition, Log eventLog) {
        try {
            EventValues eventValues = Contract.staticExtractEventParameters(eventDefinition, eventLog);

            if (eventValues == null) {
                log.warn("Could not decode {} event in tx {}", eventName, eventLog.getTransactionHash());
                return;
            }

            switch (eventName) {
                case RESERVATION_REQUESTED -> handleReservationRequested(eventValues, eventLog);
                case RESERVATION_CONFIRMED -> handleReservationConfirmed(eventValues, eventLog);
                case RESERVATION_DENIED -> handleReservationDenied(eventValues, eventLog);
                case RESERVATION_CANCELED -> handleReservationCanceled(eventValues, eventLog);
                case BOOKING_CANCELED -> handleBookingCanceled(eventValues, eventLog);
                case PROVIDER_ADDED -> handleProviderAdded(eventValues, eventLog);
                case LAB_INTENT_PROCESSED -> handleLabIntentProcessed(eventValues, eventLog);
                case RESERVATION_INTENT_PROCESSED -> handleReservationIntentProcessed(eventValues, eventLog);
                default -> log.warn("Unhandled event type: {}", eventName);
            }

        } catch (Exception e) {
            log.error("Error processing {} event (tx {}): {}", eventName, eventLog.getTransactionHash(), e.getMessage(), e);
        }
    }

    private void handleReservationRequested(EventValues eventValues, Log eventLog) {
        String renter = ((Address) eventValues.getIndexedValues().get(0)).getValue();
        BigInteger labId = ((Uint256) eventValues.getIndexedValues().get(1)).getValue();
        String reservationKey = toHex((Bytes32) eventValues.getIndexedValues().get(2));
        BigInteger start = ((Uint256) eventValues.getNonIndexedValues().get(0)).getValue();
        BigInteger end = ((Uint256) eventValues.getNonIndexedValues().get(1)).getValue();

        ReservationEventPayload payload = buildPayload(
            reservationKey,
            labId,
            Optional.ofNullable(renter),
            Optional.ofNullable(start),
            Optional.ofNullable(end),
            eventLog
        );

        dispatchReservationLifecycleEvent("requested", payload);
        persistLifecycle(payload, "PENDING");
    }

    private void handleReservationConfirmed(EventValues eventValues, Log eventLog) {
        String reservationKey = toHex((Bytes32) eventValues.getIndexedValues().get(0));
        BigInteger labId = ((Uint256) eventValues.getIndexedValues().get(1)).getValue();

        ReservationEventPayload payload = buildPayload(
            reservationKey,
            labId,
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            eventLog
        );

        dispatchReservationLifecycleEvent("confirmed", payload);
        persistLifecycle(payload, "CONFIRMED");
    }

    private void handleReservationDenied(EventValues eventValues, Log eventLog) {
        String reservationKey = toHex((Bytes32) eventValues.getIndexedValues().get(0));
        BigInteger labId = ((Uint256) eventValues.getIndexedValues().get(1)).getValue();

        ReservationEventPayload payload = buildPayload(
            reservationKey,
            labId,
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            eventLog
        );

        dispatchReservationLifecycleEvent("denied", payload);
        persistLifecycle(payload, "CANCELLED");
    }

    private void handleReservationCanceled(EventValues eventValues, Log eventLog) {
        String reservationKey = toHex((Bytes32) eventValues.getIndexedValues().get(0));
        BigInteger labId = ((Uint256) eventValues.getIndexedValues().get(1)).getValue();

        ReservationEventPayload payload = buildPayload(
            reservationKey,
            labId,
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            eventLog
        );

        dispatchReservationLifecycleEvent("canceled", payload);
        persistLifecycle(payload, "CANCELLED");
    }

    private void handleBookingCanceled(EventValues eventValues, Log eventLog) {
        String reservationKey = toHex((Bytes32) eventValues.getIndexedValues().get(0));
        BigInteger labId = ((Uint256) eventValues.getIndexedValues().get(1)).getValue();

        ReservationEventPayload payload = buildPayload(
            reservationKey,
            labId,
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            eventLog
        );

        dispatchReservationLifecycleEvent("booking-canceled", payload);
        persistLifecycle(payload, "CANCELLED");
    }

    private void handleProviderAdded(EventValues eventValues, Log eventLog) {
        String account = ((Address) eventValues.getIndexedValues().get(0)).getValue();
        String name = ((Utf8String) eventValues.getNonIndexedValues().get(0)).getValue();
        String email = ((Utf8String) eventValues.getNonIndexedValues().get(1)).getValue();
        String country = ((Utf8String) eventValues.getNonIndexedValues().get(2)).getValue();
        log.info(
            "ProviderAdded event detected (account={} tx={})",
            account,
            eventLog.getTransactionHash()
        );
        log.debug(
            "Provider metadata (name={}, email={}, country={}) stored for auditing purposes.",
            name,
            email,
            country
        );
    }

    private void handleLabIntentProcessed(EventValues eventValues, Log eventLog) {
        String requestId = toHex((Bytes32) eventValues.getIndexedValues().get(0));
        BigInteger labId = ((Uint256) eventValues.getNonIndexedValues().get(0)).getValue();
        String action = ((Utf8String) eventValues.getNonIndexedValues().get(1)).getValue();
        boolean success = ((org.web3j.abi.datatypes.Bool) eventValues.getNonIndexedValues().get(3)).getValue();
        String reason = ((Utf8String) eventValues.getNonIndexedValues().get(4)).getValue();

        log.info("LabIntentProcessed requestId={} action={} labId={} success={} tx={}", requestId, action, labId, success, eventLog.getTransactionHash());
        intentService.updateFromOnChain(
            requestId,
            success ? "executed" : "failed",
            eventLog.getTransactionHash(),
            eventLog.getBlockNumber().longValue(),
            labId != null ? labId.toString() : null,
            null,
            success ? null : reason
        );
    }

    private void handleReservationIntentProcessed(EventValues eventValues, Log eventLog) {
        String requestId = toHex((Bytes32) eventValues.getIndexedValues().get(0));
        String reservationKey = toHex((Bytes32) eventValues.getNonIndexedValues().get(0));
        String action = ((Utf8String) eventValues.getNonIndexedValues().get(1)).getValue();
        String puc = ((Utf8String) eventValues.getNonIndexedValues().get(2)).getValue();
        boolean success = ((org.web3j.abi.datatypes.Bool) eventValues.getNonIndexedValues().get(4)).getValue();
        String reason = ((Utf8String) eventValues.getNonIndexedValues().get(5)).getValue();

        log.info("ReservationIntentProcessed requestId={} action={} reservationKey={} puc={} success={} tx={}", requestId, action, reservationKey, puc, success, eventLog.getTransactionHash());
        intentService.updateFromOnChain(
            requestId,
            success ? "executed" : "failed",
            eventLog.getTransactionHash(),
            eventLog.getBlockNumber().longValue(),
            null,
            reservationKey,
            success ? null : reason
        );
    }

    private ReservationEventPayload buildPayload(
        String reservationKey,
        BigInteger labIdFromEvent,
        Optional<String> renterFromEvent,
        Optional<BigInteger> startFromEvent,
        Optional<BigInteger> endFromEvent,
        Log eventLog
    ) {
        Optional<ReservationDetails> details = fetchReservationDetails(reservationKey);

        BigInteger labId = details.map(ReservationDetails::labId).orElse(labIdFromEvent);

        Optional<String> renter = details
            .map(ReservationDetails::renter)
            .flatMap(this::normalizeNonEmptyString)
            .or(() -> renterFromEvent.flatMap(this::normalizeNonEmptyString));

        Optional<BigInteger> start = details.map(ReservationDetails::start).or(() -> startFromEvent);
        Optional<BigInteger> end = details.map(ReservationDetails::end).or(() -> endFromEvent);
        Optional<BigInteger> status = details.map(ReservationDetails::status);

        Optional<String> puc = details
            .map(ReservationDetails::puc)
            .flatMap(this::normalizeNonEmptyString);

        Optional<String> payerInstitution = details
            .map(ReservationDetails::payerInstitution)
            .flatMap(this::normalizeAddress);

        Optional<String> collectorInstitution = details
            .map(ReservationDetails::collectorInstitution)
            .flatMap(this::normalizeAddress);

        return new ReservationEventPayload(
            reservationKey,
            labId,
            renter,
            start,
            end,
            status,
            puc,
            payerInstitution,
            collectorInstitution,
            eventLog
        );
    }

    private void dispatchReservationLifecycleEvent(String action, ReservationEventPayload payload) {
        log.info(
            "Reservation {} | key={} labId={} tx={} block={}",
            action,
            payload.reservationKey(),
            payload.labId(),
            payload.rawLog().getTransactionHash(),
            payload.rawLog().getBlockNumber()
        );

        payload.status().ifPresent(status ->
            log.debug("On-chain status: {}", describeStatus(status))
        );

        payload.startEpoch().ifPresent(start ->
            log.debug(
                "Reservation window {} -> {} (epoch seconds)",
                formatEpoch(start),
                payload.endEpoch().map(this::formatEpoch).orElse("n/a")
            )
        );

        if ("confirmed".equalsIgnoreCase(action)) {
            sendReservationApprovedNotification(payload);
        }
        if ("canceled".equalsIgnoreCase(action) || "booking-canceled".equalsIgnoreCase(action)) {
            sendReservationCanceledNotification(payload);
        }

        if (ACTION_REQUESTED.equalsIgnoreCase(action)) {
            processReservationRequest(payload);
        }
    }

    private void persistLifecycle(ReservationEventPayload payload, String status) {
        Instant startTs = payload.startEpoch().map(val -> Instant.ofEpochSecond(val.longValue())).orElse(null);
        Instant endTs = payload.endEpoch().map(val -> Instant.ofEpochSecond(val.longValue())).orElse(null);
        String renter = payload.renter().orElse(null);
        String labId = payload.labId() != null ? payload.labId().toString() : null;
        try {
            reservationPersistenceService.upsertReservation(
                payload.reservationKey(),
                renter,
                labId,
                startTs,
                endTs,
                status
            );
        } catch (Exception ex) {
            log.debug("Skipping reservation persistence for {}: {}", payload.reservationKey(), ex.getMessage());
        }
    }

    private void processReservationRequest(ReservationEventPayload payload) {
        log.info(
            "Evaluating reservation request for key={} labId={} renter={} payerInstitution={} puc={}",
            payload.reservationKey(),
            payload.labId(),
            payload.renter().orElse("unknown"),
            payload.payerInstitution().orElse("n/a"),
            payload.puc().orElse("n/a")
        );

        if (!isPending(payload)) {
            log.info("Reservation {} already processed on-chain. Skipping.", payload.reservationKey());
            return;
        }

        try {
            LabMetadata metadata = loadLabMetadata(payload.labId())
                .orElseThrow(() -> new IllegalStateException("Missing metadata for lab " + payload.labId()));

            Instant start = toInstant(payload.startEpoch())
                .orElseThrow(() -> new IllegalStateException("Missing reservation start time"));
            Instant end = toInstant(payload.endEpoch())
                .orElseThrow(() -> new IllegalStateException("Missing reservation end time"));

            labMetadataService.validateAvailability(metadata, start, end, DEFAULT_RESERVATION_USER_COUNT);
            confirmReservationOnChain(payload.reservationKey());
            log.info("Reservation {} auto-approved for lab {}", payload.reservationKey(), payload.labId());
        } catch (Exception ex) {
            log.warn(
                "Auto-approval failed for reservation {} on lab {}: {}",
                payload.reservationKey(),
                payload.labId(),
                ex.getMessage()
            );
            autoDenyReservation(payload, ex.getMessage());
        }
    }

    private boolean isPending(ReservationEventPayload payload) {
        return payload.status().map(status -> status.intValue() == 0).orElse(true);
    }

    private void autoDenyReservation(ReservationEventPayload payload, String reason) {
        if (!isPending(payload)) {
            log.info(
                "Reservation {} already processed on-chain. Skipping auto-denial (reason: {}).",
                payload.reservationKey(),
                reason
            );
            return;
        }
        log.info(
            "Auto-denying reservation {} for lab {}: {}",
            payload.reservationKey(),
            payload.labId(),
            reason
        );
        denyReservationOnChain(payload.reservationKey(), reason);
    }

    private void sendReservationApprovedNotification(ReservationEventPayload payload) {
        try {
            LabMetadata metadata = loadLabMetadata(payload.labId()).orElse(null);
            String labName = (metadata != null && metadata.getName() != null && !metadata.getName().isBlank())
                ? metadata.getName()
                : "Lab " + payload.labId();

            ReservationNotificationData data = new ReservationNotificationData(
                payload.reservationKey(),
                payload.labId(),
                labName,
                payload.renter().orElse(null),
                payload.payerInstitution().orElse(null),
                payload.startEpoch().map(value -> Instant.ofEpochSecond(value.longValue())).orElse(null),
                payload.endEpoch().map(value -> Instant.ofEpochSecond(value.longValue())).orElse(null),
                payload.rawLog().getTransactionHash()
            );
            reservationNotificationService.notifyReservationApproved(data);
        } catch (Exception ex) {
            log.warn(
                "Unable to send reservation notification for {}: {}",
                payload.reservationKey(),
                ex.getMessage()
            );
        }
    }

    private void sendReservationCanceledNotification(ReservationEventPayload payload) {
        try {
            LabMetadata metadata = loadLabMetadata(payload.labId()).orElse(null);
            String labName = (metadata != null && metadata.getName() != null && !metadata.getName().isBlank())
                ? metadata.getName()
                : "Lab " + payload.labId();

            ReservationNotificationData data = new ReservationNotificationData(
                payload.reservationKey(),
                payload.labId(),
                labName,
                payload.renter().orElse(null),
                payload.payerInstitution().orElse(null),
                payload.startEpoch().map(value -> Instant.ofEpochSecond(value.longValue())).orElse(null),
                payload.endEpoch().map(value -> Instant.ofEpochSecond(value.longValue())).orElse(null),
                payload.rawLog().getTransactionHash()
            );
            reservationNotificationService.notifyReservationCancelled(data);
        } catch (Exception ex) {
            log.warn(
                "Unable to send reservation cancellation for {}: {}",
                payload.reservationKey(),
                ex.getMessage()
            );
        }
    }

    private Optional<Instant> toInstant(Optional<BigInteger> epochSeconds) {
        return epochSeconds.map(value ->
            Instant.ofEpochSecond(value.longValue())
        );
    }

    private Optional<LabMetadata> loadLabMetadata(BigInteger labId) {
        return fetchLabMetadataUri(labId).flatMap(uri -> {
            try {
                return Optional.ofNullable(labMetadataService.getLabMetadata(uri));
            } catch (RuntimeException ex) {
                log.error("Failed to load metadata for lab {} ({}): {}", labId, uri, ex.getMessage());
                return Optional.empty();
            }
        });
    }

    private Optional<String> fetchLabMetadataUri(BigInteger labId) {
        if (labId == null) {
            return Optional.empty();
        }

        String cached = labMetadataUriCache.get(labId);
        if (cached != null) {
            return Optional.of(cached);
        }

        try {
            Diamond contract = getDiamondContract();
            Diamond.Lab lab = contract.getLab(labId).send();
            if (lab == null || lab.base == null) {
                return Optional.empty();
            }
            Optional<String> uri = normalizeNonEmptyString(lab.base.uri);
            uri.ifPresent(value -> labMetadataUriCache.put(labId, value));
            return uri;
        } catch (Exception ex) {
            log.warn("Unable to fetch metadata URI for lab {}: {}", labId, ex.getMessage());
            return Optional.empty();
        }
    }

    private void confirmReservationOnChain(String reservationKey) throws Exception {
        Diamond contract = getWritableDiamondContract();
        byte[] keyBytes = reservationKeyToBytes(reservationKey);
        TransactionReceipt receipt = contract.confirmReservationRequest(keyBytes).send();
        log.info("Reservation {} confirmed on-chain (tx={})", reservationKey, receipt.getTransactionHash());
    }

    private void denyReservationOnChain(String reservationKey, String reason) {
        try {
            Diamond contract = getWritableDiamondContract();
            byte[] keyBytes = reservationKeyToBytes(reservationKey);
            TransactionReceipt receipt = contract.denyReservationRequest(keyBytes).send();
            log.info(
                "Reservation {} denied on-chain (tx={}). Reason: {}",
                reservationKey,
                receipt.getTransactionHash(),
                reason
            );
        } catch (Exception ex) {
            log.error("Failed to deny reservation {}: {}", reservationKey, ex.getMessage(), ex);
        }
    }

    private byte[] reservationKeyToBytes(String reservationKey) {
        if (reservationKey == null || reservationKey.isBlank()) {
            throw new IllegalArgumentException("Reservation key is required");
        }
        byte[] keyBytes = Numeric.hexStringToByteArray(reservationKey);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("Reservation key must be 32 bytes long");
        }
        return keyBytes;
    }

    private Diamond getWritableDiamondContract() {
        Diamond local = writableDiamond;
        if (local == null) {
            synchronized (this) {
                local = writableDiamond;
                if (local == null) {
                    Web3j web3j = walletService.getWeb3jInstance();
                    local = Diamond.load(
                        diamondContractAddress,
                        web3j,
                        getProviderCredentials(),
                        new StaticGasProvider(resolveGasPriceWei(), contractGasLimit)
                    );
                    writableDiamond = local;
                }
            }
        }
        return local;
    }

    private Credentials getProviderCredentials() {
        return institutionalWalletService.getInstitutionalCredentials();
    }

    private BigInteger resolveGasPriceWei() {
        BigDecimal gwei = (defaultGasPriceGwei == null || defaultGasPriceGwei.signum() <= 0)
            ? BigDecimal.ONE
            : defaultGasPriceGwei;
        return org.web3j.utils.Convert.toWei(gwei, org.web3j.utils.Convert.Unit.GWEI).toBigInteger();
    }

    private String describeStatus(BigInteger status) {
        if (status == null) {
            return "UNKNOWN";
        }
        return switch (status.intValue()) {
            case 0 -> "PENDING";
            case 1 -> "CONFIRMED";
            case 2 -> "IN_USE";
            case 3 -> "COMPLETED";
            case 4 -> "COLLECTED";
            case 5 -> "CANCELLED";
            default -> "UNKNOWN(" + status + ")";
        };
    }

    private String formatEpoch(BigInteger epochSeconds) {
        try {
            return Instant.ofEpochSecond(epochSeconds.longValue()).toString();
        } catch (Exception ex) {
            return epochSeconds.toString();
        }
    }

    private String toHex(Bytes32 value) {
        return Numeric.toHexString(value.getValue());
    }

    private Optional<String> normalizeNonEmptyString(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? Optional.empty() : Optional.of(trimmed);
    }

    private Optional<String> normalizeAddress(String address) {
        return normalizeNonEmptyString(address)
            .map(val -> val.toLowerCase(Locale.ROOT))
            .filter(val -> !isZeroAddress(val));
    }

    private boolean isZeroAddress(String address) {
        if (address == null || address.isBlank()) {
            return true;
        }
        String normalized = address.trim().toLowerCase(Locale.ROOT);
        return normalized.equals("0x0")
            || normalized.equals("0x")
            || normalized.equals("0x0000000000000000000000000000000000000000");
    }

    private Diamond getDiamondContract() {
        Diamond local = cachedDiamond;
        if (local == null) {
            synchronized (this) {
                local = cachedDiamond;
                if (local == null) {
                    Web3j web3j = walletService.getWeb3jInstance();
                    local = Diamond.load(
                        diamondContractAddress,
                        web3j,
                        new ReadonlyTransactionManager(web3j, diamondContractAddress),
                        new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
                    );
                    cachedDiamond = local;
                }
            }
        }
        return local;
    }

    private Optional<ReservationDetails> fetchReservationDetails(String reservationKey) {
        try {
            Diamond contract = getDiamondContract();
            byte[] keyBytes = Numeric.hexStringToByteArray(reservationKey);
            if (keyBytes.length != 32) {
                log.debug("Skipping reservation {} due to unexpected key length {}", reservationKey, keyBytes.length);
                return Optional.empty();
            }
            Diamond.Reservation reservation = contract.getReservation(keyBytes).send();
            return Optional.of(mapReservation(reservation));
        } catch (Exception ex) {
            log.debug("Unable to load reservation {}: {}", reservationKey, ex.getMessage());
            return Optional.empty();
        }
    }

    private ReservationDetails mapReservation(Diamond.Reservation reservation) {
        return new ReservationDetails(
            reservation.labId,
            reservation.renter,
            reservation.price,
            reservation.labProvider,
            reservation.status,
            reservation.start,
            reservation.end,
            reservation.puc,
            reservation.requestPeriodStart,
            reservation.requestPeriodDuration,
            reservation.payerInstitution,
            reservation.collectorInstitution
        );
    }

    private record ReservationDetails(
        BigInteger labId,
        String renter,
        BigInteger price,
        String labProvider,
        BigInteger status,
        BigInteger start,
        BigInteger end,
        String puc,
        BigInteger requestPeriodStart,
        BigInteger requestPeriodDuration,
        String payerInstitution,
        String collectorInstitution
    ) { }

    private record ReservationEventPayload(
        String reservationKey,
        BigInteger labId,
        Optional<String> renter,
        Optional<BigInteger> startEpoch,
        Optional<BigInteger> endEpoch,
        Optional<BigInteger> status,
        Optional<String> puc,
        Optional<String> payerInstitution,
        Optional<String> collectorInstitution,
        Log rawLog
    ) { }
}
