package decentralabs.blockchain.config;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.health.LabMetadata;
import decentralabs.blockchain.event.NetworkSwitchEvent;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import io.reactivex.disposables.Disposable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
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
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.EthFilter;
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
@ConditionalOnProperty(value = "features.providers.enabled", havingValue = "true", matchIfMissing = true)
public class ContractEventListenerConfig {

    private static final String RESERVATION_REQUESTED = "ReservationRequested";
    private static final String RESERVATION_CONFIRMED = "ReservationConfirmed";
    private static final String RESERVATION_DENIED = "ReservationRequestDenied";
    private static final String RESERVATION_CANCELED = "ReservationRequestCanceled";
    private static final String BOOKING_CANCELED = "BookingCanceled";

    private static final Event RESERVATION_REQUESTED_EVENT = new Event(
        RESERVATION_REQUESTED,
        Arrays.<TypeReference<?>>asList(
            new TypeReference<Address>(true) {},
            new TypeReference<Uint256>(true) {},
            new TypeReference<Uint256>() {},
            new TypeReference<Uint256>() {},
            new TypeReference<Bytes32>() {}
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

    private static final int DEFAULT_RESERVATION_USER_COUNT = 1;
    private static final String ACTION_REQUESTED = "requested";

    private static final Map<String, Event> SUPPORTED_EVENTS = Map.of(
        RESERVATION_REQUESTED, RESERVATION_REQUESTED_EVENT,
        RESERVATION_CONFIRMED, RESERVATION_CONFIRMED_EVENT,
        RESERVATION_DENIED, RESERVATION_DENIED_EVENT,
        RESERVATION_CANCELED, RESERVATION_CANCELED_EVENT,
        BOOKING_CANCELED, BOOKING_CANCELED_EVENT
    );

    private final WalletService walletService;
    private final LabMetadataService labMetadataService;
    private final InstitutionalWalletService institutionalWalletService;

    @Value("${contract.address}")
    private String diamondContractAddress;

    private volatile Diamond cachedDiamond;
    private volatile Diamond writableDiamond;

    private final Map<BigInteger, String> labMetadataUriCache = new ConcurrentHashMap<>();
    private final List<Disposable> activeSubscriptions = new java.util.concurrent.CopyOnWriteArrayList<>();

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
            for (String eventName : configuredEvents) {
                setupEventListener(web3j, diamondContractAddress, eventName);
            }
            log.info("Contract event listener configuration completed for {} events", configuredEvents.size());
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
        
        // Dispose all active subscriptions
        for (Disposable subscription : activeSubscriptions) {
            if (subscription != null && !subscription.isDisposed()) {
                subscription.dispose();
            }
        }
        activeSubscriptions.clear();
        
        // Clear cached Diamond instances (they're network-specific)
        cachedDiamond = null;
        writableDiamond = null;
        
        // Reconfigure listeners with new network
        configureContractEventListeners();
        
        log.info("Contract event listeners reconfigured for network: {}", event.getNewNetwork());
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

    /**
     * Sets up a listener for a specific contract event.
     */
    private void setupEventListener(Web3j web3j, String contractAddress, String eventName) {
        Event eventDefinition = SUPPORTED_EVENTS.get(eventName);
        if (eventDefinition == null) {
            log.warn("Event '{}' is not supported and will be ignored", eventName);
            return;
        }

        String eventSignature = EventEncoder.encode(eventDefinition);
        EthFilter filter = new EthFilter(
            resolveStartBlockParameter(),
            DefaultBlockParameterName.LATEST,
            contractAddress
        );

        log.info("Setting up listener for '{}' with signature {}", eventName, eventSignature);

        Disposable subscription = web3j.ethLogFlowable(filter).subscribe(
            eventLog -> handleLogIfMatches(eventName, eventDefinition, eventSignature, eventLog),
            error -> log.error("Error listening for {} events: {}", eventName, error.getMessage(), error),
            () -> log.info("Event listener for {} completed", eventName)
        );
        
        // Store subscription so it can be disposed on network switch
        activeSubscriptions.add(subscription);
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
                default -> log.warn("Unhandled event type: {}", eventName);
            }

        } catch (Exception e) {
            log.error("Error processing {} event (tx {}): {}", eventName, eventLog.getTransactionHash(), e.getMessage(), e);
        }
    }

    private void handleReservationRequested(EventValues eventValues, Log eventLog) {
        String renter = ((Address) eventValues.getIndexedValues().get(0)).getValue();
        BigInteger labId = ((Uint256) eventValues.getIndexedValues().get(1)).getValue();
        BigInteger start = ((Uint256) eventValues.getNonIndexedValues().get(0)).getValue();
        BigInteger end = ((Uint256) eventValues.getNonIndexedValues().get(1)).getValue();
        String reservationKey = toHex((Bytes32) eventValues.getNonIndexedValues().get(2));

        ReservationEventPayload payload = buildPayload(
            reservationKey,
            labId,
            Optional.ofNullable(renter),
            Optional.ofNullable(start),
            Optional.ofNullable(end),
            eventLog
        );

        dispatchReservationLifecycleEvent("requested", payload);
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
            "Reservation window {} → {} (epoch seconds)",
            formatEpoch(start),
            payload.endEpoch().map(this::formatEpoch).orElse("n/a")
        )
    );

    if (ACTION_REQUESTED.equalsIgnoreCase(action)) {
        processReservationRequest(payload);
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

        LocalDateTime start = toUtcDateTime(payload.startEpoch())
            .orElseThrow(() -> new IllegalStateException("Missing reservation start time"));
        LocalDateTime end = toUtcDateTime(payload.endEpoch())
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
    private Optional<LocalDateTime> toUtcDateTime(Optional<BigInteger> epochSeconds) {
        return epochSeconds.map(value ->
            LocalDateTime.ofInstant(Instant.ofEpochSecond(value.longValue()), ZoneOffset.UTC)
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

    private DefaultBlockParameter resolveStartBlockParameter() {
        if (startBlock == null || startBlock.isBlank()) {
            return DefaultBlockParameterName.LATEST;
        }

        String normalized = startBlock.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "earliest" -> DefaultBlockParameterName.EARLIEST;
            case "latest" -> DefaultBlockParameterName.LATEST;
            case "pending" -> DefaultBlockParameterName.PENDING;
            default -> {
                try {
                    BigInteger blockNumber = normalized.startsWith("0x")
                        ? new BigInteger(normalized.substring(2), 16)
                        : new BigInteger(normalized);
                    yield DefaultBlockParameter.valueOf(blockNumber);
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException(
                        "Invalid contract.event.start.block: " + startBlock, ex);
                }
            }
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
