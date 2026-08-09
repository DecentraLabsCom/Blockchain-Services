package decentralabs.blockchain.service.labadmin;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.labadmin.LabAdminAssetResponse;
import decentralabs.blockchain.dto.labadmin.LabAdminCancellationOption;
import decentralabs.blockchain.dto.labadmin.LabAdminPublishRequest;
import decentralabs.blockchain.dto.labadmin.LabAdminReservation;
import decentralabs.blockchain.dto.labadmin.LabAdminTransactionResponse;
import decentralabs.blockchain.dto.health.LabMetadata;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.guacamole.GuacamoleProvisioningService;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.provider.StationCapacityService;
import decentralabs.blockchain.service.wallet.InstitutionalTxManagerProvider;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.CreditUnitConverter;
import decentralabs.blockchain.util.LogSanitizer;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

@Service
@RequiredArgsConstructor
@Slf4j
public class LabAdminService {

    private static final long MAX_ASSET_BYTES = 10L * 1024L * 1024L;
    private static final List<String> IMAGE_TYPES = List.of("image/jpeg", "image/png", "image/webp", "image/gif");
    private static final List<String> DOC_TYPES = List.of("application/pdf");
    private static final Pattern BYTES32_PATTERN = Pattern.compile("0x[0-9a-fA-F]{64}");
    private static final String ZERO_BYTES32 = "0x" + "0".repeat(64);
    private static final String ZERO_ADDRESS = "0x" + "0".repeat(40);
    private static final String ERC721_TRANSFER_TOPIC =
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    private static final BigInteger STATUS_PENDING = BigInteger.ZERO;
    private static final BigInteger STATUS_CONFIRMED = BigInteger.ONE;
    private static final BigInteger STATUS_ACCESS_AUTHORIZED = BigInteger.valueOf(2);
    private static final BigInteger PROVIDER_SERVICE_FAILURE_REASON = BigInteger.valueOf(8);
    private static final long SESSION_ATTESTATION_GRACE_SECONDS = 86_400L;
    private static final long FULL_DAY_SECONDS = 86_400L;
    private static final int DEFAULT_RESERVATION_PAGE_SIZE = 100;
    private static final int MAX_RESERVATION_PAGE_SIZE = 500;
    private static final int ON_CHAIN_RESERVATION_PAGE_SIZE = 100;
    private static final int DEFAULT_ACTIONABLE_RPC_BUDGET = 500;

    public record LabAdminDeleteAssetResponse(boolean success, boolean deleted, String path) {}

    private record ReservationCursor(BigInteger labId, BigInteger offset) {}

    private static final class RpcBudgetExceededException extends RuntimeException {
        private RpcBudgetExceededException() {
            super("Actionable reservation RPC budget exhausted");
        }
    }

    private static final class RpcBudget {
        private final int maximum;
        private int used;

        private RpcBudget(int maximum) {
            this.maximum = maximum;
        }

        private void consume() {
            if (used >= maximum) {
                throw new RpcBudgetExceededException();
            }
            used++;
        }
    }

    private final InstitutionalWalletService institutionalWalletService;
    private final InstitutionalTxManagerProvider txManagerProvider;
    private final WalletService walletService;
    private final BackendUrlResolver backendUrlResolver;
    private final ObjectMapper objectMapper;
    private final GuacamoleProvisioningService guacamoleProvisioningService;
    private final LabContentRetentionService contentRetentionService;
    private final LabMetadataService labMetadataService;
    private final StationCapacityService stationCapacityService;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${lab.content.base-path:/app/lab-content}")
    private String contentBasePath;

    @Value("${fmu.data.path:/app/fmu-data}")
    private String fmuDataPath;

    @Value("${ethereum.gas.price.default:1}")
    private BigInteger defaultGasPriceGwei;

    @Value("${ethereum.gas.price.strategy:network}")
    private String gasPriceStrategy;

    @Value("${ethereum.gas.limit.contract:300000}")
    private BigInteger contractGasLimit;

    @Value("${provider.puc-hash:}")
    private String configuredCreatorPucHash;

    @Value("${lab.admin.reservations.rpc-budget:500}")
    private int actionableReservationsRpcBudget = DEFAULT_ACTIONABLE_RPC_BUDGET;

    public Map<String, Object> status() {
        String wallet = institutionalWalletService.getInstitutionalWalletAddress();
        boolean walletConfigured = institutionalWalletService.isConfigured();
        boolean provider = walletConfigured && walletService.isLabProvider(wallet);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("walletConfigured", walletConfigured);
        result.put("providerAddress", wallet);
        result.put("isProvider", provider);
        result.put("creatorPucHashConfigured", hasText(configuredCreatorPucHash));
        result.put("publicBaseUrl", publicBaseUrl());
        result.put("contentBaseUrl", publicBaseUrl() + "/lab-content");
        result.put("recommendedRemoteAccessURI", publicBaseUrl() + "/guacamole");
        result.put("recommendedFmuAccessURI", publicBaseUrl() + "/fmu");
        result.put("fmuInventory", listFmus());
        result.put("guacamoleCatalogAvailable", guacamoleProvisioningService.isConfigured());
        return result;
    }

    public Map<String, Object> guacamoleConnections() {
        return Map.of(
            "success", true,
            "connections", guacamoleProvisioningService.listSafeConnections()
        );
    }

    public Map<String, Object> listLabs() {
        String wallet = requireProviderWallet();
        List<Map<String, Object>> labs = new ArrayList<>();
        for (BigInteger labId : walletService.getLabsOwnedByProvider(wallet)) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("labId", labId.toString());
            try {
                Diamond.Lab lab = loadReadonlyDiamond().getLab(labId).send();
                item.put("uri", lab.base.uri);
                item.put("price", lab.base.price.toString());
                item.put("accessURI", lab.base.accessURI);
                item.put("accessKey", lab.base.accessKey);
                item.put("resourceType", lab.base.resourceType.intValue());
                item.put("listed", loadReadonlyDiamond().isLabListed(labId).send());
            } catch (Exception ex) {
                log.debug("Unable to load details for lab {}", labId, ex);
                item.put("error", "Unable to load lab details");
            }
            labs.add(item);
        }
        return Map.of("success", true, "providerAddress", wallet, "labs", labs);
    }

    public Map<String, Object> listUpcomingReservations() throws Exception {
        return listUpcomingReservations(0, null);
    }

    public Map<String, Object> listUpcomingReservations(Integer offset, Integer limit) throws Exception {
        return listReservations(false, offset, limit);
    }

    public Map<String, Object> listActionableReservations() throws Exception {
        return listActionableReservations(0, null, null);
    }

    public Map<String, Object> listActionableReservations(Integer offset, Integer limit) throws Exception {
        return listActionableReservations(offset, limit, null);
    }

    public Map<String, Object> listActionableReservations(Integer offset, Integer limit, String cursor)
        throws Exception {
        String wallet = requireProviderWallet();
        Diamond diamond = loadReadonlyDiamond();
        long now = Instant.now().getEpochSecond();
        int safeOffset = normalizeReservationOffset(offset);
        int safeLimit = normalizeReservationPageSize(limit);
        List<BigInteger> labIds = new ArrayList<>(walletService.getLabsOwnedByProvider(wallet));
        Map<BigInteger, String> labNames = new HashMap<>();
        Map<String, String> institutionNames = new HashMap<>();
        List<LabAdminReservation> reservations = new ArrayList<>(safeLimit);
        RpcBudget budget = new RpcBudget(Math.max(1, actionableReservationsRpcBudget));

        ReservationCursor start = hasText(cursor)
            ? decodeReservationCursor(cursor)
            : (labIds.isEmpty() ? null : new ReservationCursor(labIds.get(0), BigInteger.ZERO));
        int startLabIndex = start == null ? 0 : labIds.indexOf(start.labId());
        if (start != null && startLabIndex < 0) {
            throw new IllegalArgumentException("Reservation cursor does not reference an owned lab");
        }
        BigInteger startRawOffset = start == null ? BigInteger.ZERO : start.offset();
        int actionableToSkip = hasText(cursor) ? 0 : safeOffset;
        String nextCursor = null;
        boolean budgetExhausted = false;

        outer:
        for (int labIndex = startLabIndex; labIndex < labIds.size(); labIndex++) {
            BigInteger labId = labIds.get(labIndex);
            BigInteger rawOffset = labIndex == startLabIndex ? startRawOffset : BigInteger.ZERO;
            while (true) {
                Diamond.ReservationKeyPage reservationPage;
                try {
                    budget.consume();
                    reservationPage = diamond.getReservationsOfTokenPaginated(
                        labId,
                        rawOffset,
                        BigInteger.valueOf(ON_CHAIN_RESERVATION_PAGE_SIZE)
                    ).send();
                } catch (RpcBudgetExceededException ex) {
                    nextCursor = encodeReservationCursor(labId, rawOffset);
                    budgetExhausted = true;
                    break outer;
                } catch (Exception ex) {
                    log.debug("Unable to load reservation page at offset {} for lab {}", rawOffset, labId, ex);
                    nextCursor = encodeReservationCursor(labId, rawOffset);
                    break outer;
                }

                if (reservationPage == null || reservationPage.keys() == null
                    || reservationPage.keys().isEmpty()) {
                    break;
                }
                BigInteger rawTotal = reservationPage.total() == null
                    ? rawOffset.add(BigInteger.valueOf(reservationPage.keys().size()))
                    : reservationPage.total();

                for (int pageIndex = 0; pageIndex < reservationPage.keys().size(); pageIndex++) {
                    BigInteger currentRawOffset = rawOffset.add(BigInteger.valueOf(pageIndex));
                    byte[] key = reservationPage.keys().get(pageIndex);
                    try {
                        budget.consume();
                        Diamond.Reservation reservation = diamond.getReservation(key).send();
                        if (!hasReservation(reservation)
                            || !wallet.equalsIgnoreCase(reservation.labProvider)) {
                            continue;
                        }
                        Boolean sessionStarted = readSessionStartedStatus(diamond, key, reservation, budget);
                        List<LabAdminCancellationOption> cancellationOptions = providerCancellationOptions(
                            reservation, now, sessionStarted
                        );
                        if (cancellationOptions.isEmpty()) {
                            continue;
                        }
                        if (actionableToSkip > 0) {
                            actionableToSkip--;
                            continue;
                        }

                        String labName = labNames.get(reservation.labId);
                        if (!labNames.containsKey(reservation.labId)) {
                            labName = resolveLabName(diamond, reservation.labId, budget);
                            labNames.put(reservation.labId, labName);
                        }
                        String institutionAddress = reservation.payerInstitution;
                        String institutionKey = normalizeAddressKey(institutionAddress);
                        String institutionName = institutionNames.get(institutionKey);
                        if (!institutionNames.containsKey(institutionKey)) {
                            institutionName = resolveInstitutionName(diamond, institutionAddress, budget);
                            institutionNames.put(institutionKey, institutionName);
                        }
                        reservations.add(toLabAdminReservation(
                            key, reservation, labName, institutionName, cancellationOptions
                        ));
                        if (reservations.size() >= safeLimit) {
                            nextCursor = nextReservationCursor(
                                labIds, labIndex, currentRawOffset.add(BigInteger.ONE), rawTotal
                            );
                            break outer;
                        }
                    } catch (RpcBudgetExceededException ex) {
                        nextCursor = encodeReservationCursor(labId, currentRawOffset);
                        budgetExhausted = true;
                        break outer;
                    } catch (Exception ex) {
                        log.debug("Unable to load actionable reservation at offset {} for lab {}", currentRawOffset, labId, ex);
                    }
                }

                rawOffset = rawOffset.add(BigInteger.valueOf(reservationPage.keys().size()));
                if (rawOffset.compareTo(rawTotal) >= 0) {
                    break;
                }
            }
        }

        int nextOffset = safeOffset > Integer.MAX_VALUE - reservations.size()
            ? Integer.MAX_VALUE
            : safeOffset + reservations.size();
        boolean hasMore = nextCursor != null;
        Map<String, Object> pagination = new LinkedHashMap<>();
        pagination.put("offset", safeOffset);
        pagination.put("limit", safeLimit);
        pagination.put("returned", reservations.size());
        pagination.put("nextOffset", nextOffset);
        pagination.put("hasMore", hasMore);
        if (nextCursor != null) {
            pagination.put("nextCursor", nextCursor);
        }
        pagination.put("rpcCalls", budget.used);
        pagination.put("rpcBudget", budget.maximum);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("providerAddress", wallet);
        result.put("asOf", now);
        result.put("view", "actionable");
        result.put("count", reservations.size());
        result.put("offset", safeOffset);
        result.put("limit", safeLimit);
        result.put("nextOffset", nextOffset);
        result.put("hasMore", hasMore);
        result.put("truncated", hasMore);
        result.put("rpcBudgetExhausted", budgetExhausted);
        if (nextCursor != null) {
            result.put("nextCursor", nextCursor);
        }
        result.put("pagination", pagination);
        result.put("reservations", List.copyOf(reservations));
        return result;
    }

    private ReservationCursor decodeReservationCursor(String cursor) {
        try {
            String decoded = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
            String[] parts = decoded.split("\\|", -1);
            if (parts.length != 3 || !"v1".equals(parts[0])) {
                throw new IllegalArgumentException("Unsupported reservation cursor");
            }
            BigInteger labId = new BigInteger(parts[1]);
            BigInteger offset = new BigInteger(parts[2]);
            if (labId.signum() <= 0 || offset.signum() < 0) {
                throw new IllegalArgumentException("Invalid reservation cursor");
            }
            return new ReservationCursor(labId, offset);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid reservation cursor", ex);
        }
    }

    private String encodeReservationCursor(BigInteger labId, BigInteger offset) {
        String value = "v1|" + labId + "|" + offset;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private String nextReservationCursor(
        List<BigInteger> labIds,
        int currentLabIndex,
        BigInteger nextRawOffset,
        BigInteger currentLabTotal
    ) {
        if (nextRawOffset.compareTo(currentLabTotal) < 0) {
            return encodeReservationCursor(labIds.get(currentLabIndex), nextRawOffset);
        }
        if (currentLabIndex + 1 < labIds.size()) {
            return encodeReservationCursor(labIds.get(currentLabIndex + 1), BigInteger.ZERO);
        }
        return null;
    }

    private Map<String, Object> listReservations(boolean actionableOnly, Integer offset, Integer limit) throws Exception {
        String wallet = requireProviderWallet();
        Diamond diamond = loadReadonlyDiamond();
        long now = Instant.now().getEpochSecond();
        List<LabAdminReservation> reservations = new ArrayList<>();
        Map<BigInteger, String> labNames = new HashMap<>();
        Map<String, String> institutionNames = new HashMap<>();
        int safeOffset = normalizeReservationOffset(offset);
        int safeLimit = normalizeReservationPageSize(limit);

        for (BigInteger labId : walletService.getLabsOwnedByProvider(wallet)) {
            BigInteger reservationCount;
            try {
                reservationCount = diamond.getReservationsOfToken(labId).send();
            } catch (Exception ex) {
                log.debug("Unable to load reservations for lab {}", labId, ex);
                continue;
            }
            if (reservationCount == null || reservationCount.signum() <= 0) {
                continue;
            }

            for (BigInteger index = BigInteger.ZERO;
                 index.compareTo(reservationCount) < 0;
                 index = index.add(BigInteger.ONE)) {
                try {
                    byte[] key = diamond.getReservationOfTokenByIndex(labId, index).send();
                    Diamond.Reservation reservation = diamond.getReservation(key).send();
                    if (!actionableOnly && !isUpcomingReservation(reservation, now)) {
                        continue;
                    }
                    if (!hasReservation(reservation) || !wallet.equalsIgnoreCase(reservation.labProvider)) {
                        continue;
                    }
                    Boolean sessionStarted = readSessionStartedStatus(diamond, key, reservation);
                    List<LabAdminCancellationOption> cancellationOptions = providerCancellationOptions(
                        reservation, now, sessionStarted
                    );
                    if (actionableOnly && cancellationOptions.isEmpty()) {
                        continue;
                    }
                    String labName = labNames.get(reservation.labId);
                    if (!labNames.containsKey(reservation.labId)) {
                        labName = resolveLabName(diamond, reservation.labId);
                        labNames.put(reservation.labId, labName);
                    }
                    String institutionAddress = reservation.payerInstitution;
                    String institutionKey = normalizeAddressKey(institutionAddress);
                    String institutionName = institutionNames.get(institutionKey);
                    if (!institutionNames.containsKey(institutionKey)) {
                        institutionName = resolveInstitutionName(diamond, institutionAddress);
                        institutionNames.put(institutionKey, institutionName);
                    }
                    reservations.add(toLabAdminReservation(
                        key, reservation, labName, institutionName, cancellationOptions
                    ));
                } catch (Exception ex) {
                    log.debug("Unable to load reservation {} for lab {}", index, labId, ex);
                }
            }
        }

        reservations.sort((left, right) -> {
            int comparison = Long.compare(left.start(), right.start());
            if (comparison != 0) return comparison;
            comparison = left.labId().compareTo(right.labId());
            if (comparison != 0) return comparison;
            return left.reservationKey().compareTo(right.reservationKey());
        });
        int total = reservations.size();
        int fromIndex = Math.min(safeOffset, total);
        int toIndex = Math.min(total, fromIndex + safeLimit);
        List<LabAdminReservation> page = List.copyOf(reservations.subList(fromIndex, toIndex));
        boolean hasMore = toIndex < total;
        Map<String, Object> pagination = Map.of(
            "offset", fromIndex,
            "limit", safeLimit,
            "returned", page.size(),
            "total", total,
            "nextOffset", toIndex,
            "hasMore", hasMore
        );

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("providerAddress", wallet);
        result.put("asOf", now);
        result.put("view", actionableOnly ? "actionable" : "upcoming");
        result.put("count", page.size());
        result.put("totalCount", total);
        result.put("offset", fromIndex);
        result.put("limit", safeLimit);
        result.put("nextOffset", toIndex);
        result.put("hasMore", hasMore);
        result.put("truncated", hasMore);
        result.put("pagination", pagination);
        result.put("reservations", page);
        return result;
    }

    private int normalizeReservationOffset(Integer offset) {
        if (offset == null) return 0;
        if (offset < 0) throw new IllegalArgumentException("Reservation offset must be non-negative");
        return offset;
    }

    private int normalizeReservationPageSize(Integer limit) {
        if (limit == null) return DEFAULT_RESERVATION_PAGE_SIZE;
        if (limit <= 0) throw new IllegalArgumentException("Reservation limit must be positive");
        return Math.min(limit, MAX_RESERVATION_PAGE_SIZE);
    }

    public LabAdminTransactionResponse cancelReservation(
        String reservationKey,
        Integer reasonCode,
        String idempotencyKey
    ) throws Exception {
        String normalizedKey = normalizeReservationKey(reservationKey);
        BigInteger normalizedReason = requireProviderReason(reasonCode);
        String commandKey = requireReservationIdempotencyKey(idempotencyKey);
        String wallet = requireProviderWallet();
        byte[] key = Numeric.hexStringToByteArray(normalizedKey);
        Diamond diamond = loadReadonlyDiamond();
        Diamond.Reservation reservation = diamond.getReservation(key).send();
        if (!hasReservation(reservation)) {
            throw new IllegalArgumentException("Reservation was not found");
        }
        if (!wallet.equalsIgnoreCase(reservation.labProvider)
            || !walletService.isLabOwnedByProvider(wallet, reservation.labId)) {
            throw new IllegalStateException("Reservation is not owned by this provider wallet");
        }
        long now = Instant.now().getEpochSecond();
        boolean serviceFailure = PROVIDER_SERVICE_FAILURE_REASON.equals(normalizedReason);
        if (!serviceFailure && (reservation.start == null || reservation.start.longValueExact() <= now)) {
            throw new IllegalStateException("Reservation has already started or is no longer cancellable");
        }

        if (serviceFailure
            && (STATUS_CONFIRMED.equals(reservation.status) || STATUS_ACCESS_AUTHORIZED.equals(reservation.status))) {
            Boolean sessionStarted = readSessionStartedStatus(diamond, key, reservation);
            boolean eligible = providerCancellationOptions(reservation, now, sessionStarted).stream()
                .anyMatch(option -> option.reasonCode() == PROVIDER_SERVICE_FAILURE_REASON.intValue());
            if (!eligible) {
                throw new IllegalStateException(
                    "Provider service-failure cancellation is not currently eligible"
                );
            }
        }

        String action;
        TransactionReceipt receipt;
        if (STATUS_PENDING.equals(reservation.status)) {
            if (!isPendingProviderReason(normalizedReason)) {
                throw new IllegalArgumentException(
                    "Pending reservations require a provider reason code: 1, 2, 6 or 7"
                );
            }
            action = "denyReservationRequestWithReason";
            receipt = loadWritableDiamond(operationKey("deny-reservation", normalizedKey, commandKey))
                .denyReservationRequestWithReason(key, normalizedReason)
                .send();
        } else if (STATUS_CONFIRMED.equals(reservation.status)
            || (serviceFailure && STATUS_ACCESS_AUTHORIZED.equals(reservation.status))) {
            action = "cancelConfirmedBookingByProvider";
            receipt = loadWritableDiamond(operationKey("cancel-reservation", normalizedKey, commandKey))
                .cancelConfirmedBookingByProvider(key, normalizedReason)
                .send();
        } else {
            throw new IllegalStateException("Reservation status is not cancellable: "
                + describeReservationStatus(reservation.status));
        }

        if (receipt == null || !receipt.isStatusOK()) {
            throw new IllegalStateException("Reservation cancellation transaction was reverted");
        }
        return new LabAdminTransactionResponse(
            true,
            action,
            receipt.getTransactionHash(),
            receipt.getStatus(),
            reservation.labId,
            null
        );
    }

    private boolean isUpcomingReservation(Diamond.Reservation reservation, long now) {
        if (!hasReservation(reservation) || reservation.start == null) {
            return false;
        }
        int status = reservation.status.intValue();
        return (status == STATUS_PENDING.intValue()
            || status == STATUS_CONFIRMED.intValue()
            || status == STATUS_ACCESS_AUTHORIZED.intValue())
            && reservation.start.longValueExact() >= now;
    }

    private LabAdminReservation toLabAdminReservation(
        byte[] key,
        Diamond.Reservation reservation,
        String labName,
        String institutionName,
        List<LabAdminCancellationOption> cancellationOptions
    ) {
        int status = reservation.status.intValueExact();
        long start = reservation.start.longValueExact();
        long end = reservation.end.longValueExact();
        return new LabAdminReservation(
            Numeric.toHexString(key),
            reservation.labId.toString(),
            labName,
            reservation.renter,
            institutionName,
            reservation.payerInstitution,
            status,
            describeReservationStatus(reservation.status),
            start,
            end,
            reservation.price.toString(),
            CreditUnitConverter.formatRawCredits(reservation.price),
            reservation.providerShare.toString(),
            CreditUnitConverter.formatRawCredits(reservation.providerShare),
            !cancellationOptions.isEmpty(),
            cancellationOptions
        );
    }

    private Boolean readSessionStartedStatus(
        Diamond diamond,
        byte[] reservationKey,
        Diamond.Reservation reservation
    ) {
        if (!STATUS_CONFIRMED.equals(reservation.status) && !STATUS_ACCESS_AUTHORIZED.equals(reservation.status)) {
            return Boolean.FALSE;
        }
        try {
            var call = diamond.hasReservationSessionStarted(reservationKey);
            return call == null ? null : call.send();
        } catch (Exception ex) {
            log.debug("Unable to determine SessionStarted status for provider reservation", ex);
            return null;
        }
    }

    private Boolean readSessionStartedStatus(
        Diamond diamond,
        byte[] reservationKey,
        Diamond.Reservation reservation,
        RpcBudget budget
    ) {
        if (!STATUS_CONFIRMED.equals(reservation.status) && !STATUS_ACCESS_AUTHORIZED.equals(reservation.status)) {
            return Boolean.FALSE;
        }
        try {
            var call = diamond.hasReservationSessionStarted(reservationKey);
            if (call == null) {
                return null;
            }
            budget.consume();
            return call.send();
        } catch (RpcBudgetExceededException ex) {
            throw ex;
        } catch (Exception ex) {
            log.debug("Unable to determine SessionStarted status for provider reservation", ex);
            return null;
        }
    }

    private List<LabAdminCancellationOption> providerCancellationOptions(
        Diamond.Reservation reservation,
        long now,
        Boolean sessionStarted
    ) {
        if (!hasReservation(reservation) || reservation.start == null || reservation.status == null) {
            return List.of();
        }

        long start = reservation.start.longValueExact();
        int status = reservation.status.intValueExact();
        if (status == STATUS_PENDING.intValue()) {
            if (start <= now) {
                return List.of();
            }
            long deadline = pendingCancellationDeadline(reservation, start);
            return List.of(
                new LabAdminCancellationOption(1, "Manual cancellation", deadline, -1),
                new LabAdminCancellationOption(2, "Not eligible", deadline, 0),
                new LabAdminCancellationOption(6, "Technical issue", deadline, 0),
                new LabAdminCancellationOption(7, "Provider unavailable", deadline, 0)
            );
        }

        List<LabAdminCancellationOption> options = new ArrayList<>();
        if (status == STATUS_CONFIRMED.intValue() && start > now) {
            int penalty = start - now >= FULL_DAY_SECONDS ? -1 : -2;
            options.add(new LabAdminCancellationOption(1, "Manual cancellation", start, penalty));
            options.add(new LabAdminCancellationOption(6, "Technical issue", start, penalty));
            options.add(new LabAdminCancellationOption(7, "Provider unavailable", start, penalty));
        }

        if ((status == STATUS_CONFIRMED.intValue() || status == STATUS_ACCESS_AUTHORIZED.intValue())
            && Boolean.FALSE.equals(sessionStarted)
            && reservation.end != null) {
            long deadline = sessionAttestationDeadline(reservation.end);
            if (now <= deadline) {
                options.add(new LabAdminCancellationOption(8, "Service failure", deadline, -3));
            }
        }
        return List.copyOf(options);
    }

    private long pendingCancellationDeadline(Diamond.Reservation reservation, long start) {
        if (reservation.requestPeriodStart == null
            || reservation.requestPeriodDuration == null
            || reservation.requestPeriodStart.signum() == 0
            || reservation.requestPeriodDuration.signum() == 0) {
            return start;
        }
        try {
            long requestDeadline = reservation.requestPeriodStart
                .add(reservation.requestPeriodDuration)
                .longValueExact();
            return Math.min(start, requestDeadline);
        } catch (ArithmeticException ex) {
            return start;
        }
    }

    private long sessionAttestationDeadline(BigInteger reservationEnd) {
        try {
            return Math.addExact(reservationEnd.longValueExact(), SESSION_ATTESTATION_GRACE_SECONDS);
        } catch (ArithmeticException ex) {
            return Long.MAX_VALUE;
        }
    }

    private String resolveLabName(Diamond diamond, BigInteger labId) {
        return resolveLabName(diamond, labId, null);
    }

    private String resolveLabName(Diamond diamond, BigInteger labId, RpcBudget budget) {
        try {
            if (budget != null) {
                budget.consume();
            }
            Diamond.Lab lab = diamond.getLab(labId).send();
            if (lab == null || lab.base == null || !hasText(lab.base.uri)) {
                return null;
            }
            var metadata = labMetadataService.getLabMetadataForLab(labId);
            return metadata == null || !hasText(metadata.getName())
                ? null
                : metadata.getName().trim();
        } catch (RpcBudgetExceededException ex) {
            throw ex;
        } catch (Exception ex) {
            log.debug("Unable to resolve name for lab {}", labId, ex);
            return null;
        }
    }

    private String resolveInstitutionName(Diamond diamond, String institutionAddress) {
        return resolveInstitutionName(diamond, institutionAddress, null);
    }

    private String resolveInstitutionName(Diamond diamond, String institutionAddress, RpcBudget budget) {
        if (!hasText(institutionAddress) || ZERO_ADDRESS.equalsIgnoreCase(institutionAddress)) {
            return null;
        }
        try {
            if (budget != null) {
                budget.consume();
            }
            String[] organizations = diamond
                .getRegisteredSchacHomeOrganizations(institutionAddress)
                .send();
            if (organizations == null) {
                return null;
            }
            List<String> names = new ArrayList<>();
            for (String organization : organizations) {
                if (!hasText(organization)) {
                    continue;
                }
                String normalized = organization.trim();
                if (!names.contains(normalized)) {
                    names.add(normalized);
                }
            }
            return String.join(", ", names);
        } catch (RpcBudgetExceededException ex) {
            throw ex;
        } catch (Exception ex) {
            log.debug("Unable to resolve institution name for wallet {}", institutionAddress, ex);
            return null;
        }
    }

    private String normalizeAddressKey(String address) {
        return address == null ? "" : address.toLowerCase(Locale.ROOT);
    }

    private boolean hasReservation(Diamond.Reservation reservation) {
        return reservation != null
            && reservation.labId != null
            && reservation.renter != null
            && !ZERO_ADDRESS.equalsIgnoreCase(reservation.renter)
            && reservation.status != null;
    }

    private String normalizeReservationKey(String value) {
        String normalized = value == null ? "" : value.trim();
        if (!BYTES32_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("reservationKey must be a 0x-prefixed bytes32 value");
        }
        return normalized.toLowerCase(Locale.ROOT);
    }

    private BigInteger requireProviderReason(Integer reasonCode) {
        if (reasonCode == null || reasonCode < 1 || reasonCode > 255) {
            throw new IllegalArgumentException("reasonCode must be between 1 and 255");
        }
        return BigInteger.valueOf(reasonCode.longValue());
    }

    private String requireReservationIdempotencyKey(String idempotencyKey) {
        String normalized = idempotencyKey == null ? "" : idempotencyKey.trim();
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Idempotency-Key is required for reservation cancellation");
        }
        if (normalized.length() > 128) {
            throw new IllegalArgumentException("Idempotency-Key must not exceed 128 characters");
        }
        return normalized;
    }

    private boolean isPendingProviderReason(BigInteger reasonCode) {
        return BigInteger.ONE.equals(reasonCode)
            || BigInteger.valueOf(2).equals(reasonCode)
            || BigInteger.valueOf(6).equals(reasonCode)
            || BigInteger.valueOf(7).equals(reasonCode);
    }

    private String describeReservationStatus(BigInteger status) {
        if (status == null) {
            return "UNKNOWN";
        }
        return switch (status.intValue()) {
            case 0 -> "PENDING";
            case 1 -> "CONFIRMED";
            case 2 -> "ACCESS_AUTHORIZED";
            case 3 -> "COLLECTED";
            case 4 -> "CANCELLED";
            default -> "UNKNOWN(" + status + ")";
        };
    }

    public LabAdminAssetResponse saveAsset(String requestedContentId, String kind, MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File is required");
        }
        if (file.getSize() > MAX_ASSET_BYTES) {
            throw new IllegalArgumentException("File exceeds 10 MB limit");
        }
        String normalizedKind = normalizeAssetKind(kind);
        String contentType = Optional.ofNullable(file.getContentType()).orElse("").toLowerCase(Locale.ROOT);
        if ("images".equals(normalizedKind) && !IMAGE_TYPES.contains(contentType)) {
            throw new IllegalArgumentException("Only JPEG, PNG, WebP or GIF images are allowed");
        }
        if ("docs".equals(normalizedKind) && !DOC_TYPES.contains(contentType)) {
            throw new IllegalArgumentException("Only PDF documents are allowed");
        }

        String contentId = normalizeContentId(requestedContentId);
        String fileName = safeFileName(file.getOriginalFilename(), contentType, normalizedKind);
        Path targetDir = contentRoot().resolve("content").resolve(contentId).resolve(normalizedKind).normalize();
        ensureWithinContentRoot(targetDir);
        if (contentRetentionService.isTombstoned("content/" + contentId + "/metadata.json")) {
            throw new IllegalStateException("Lab content is retained after deletion");
        }
        Files.createDirectories(targetDir);
        Path target = targetDir.resolve(fileName).normalize();
        ensureWithinContentRoot(target);
        Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

        String relative = "content/" + contentId + "/" + normalizedKind + "/" + fileName;
        return new LabAdminAssetResponse(
            true,
            contentId,
            "/" + relative,
            publicBaseUrl() + "/lab-content/" + relative,
            contentType,
            file.getSize()
        );
    }

    public LabAdminDeleteAssetResponse deleteAsset(String assetPath) throws IOException {
        String relative = normalizeUploadedAssetPath(assetPath);
        Path target = contentRoot().resolve(relative).normalize();
        ensureWithinContentRoot(target);
        boolean deleted = Files.deleteIfExists(target);
        return new LabAdminDeleteAssetResponse(true, deleted, "/" + relative);
    }

    public LabAdminTransactionResponse publish(LabAdminPublishRequest request) throws Exception {
        return publish(request, null);
    }

    /**
     * Publishes one business command. The idempotency key belongs to the HTTP
     * command instance and is required so the durable outbox can coordinate
     * retries across replicas.
     */
    public LabAdminTransactionResponse publish(LabAdminPublishRequest request, String idempotencyKey) throws Exception {
        String commandKey = requirePublishIdempotencyKey(idempotencyKey);
        String wallet = requireProviderWallet();
        String creatorPucHash = resolveCreatorPucHash(request);
        BigInteger resourceType = normalizeResourceType(request.resourceType());
        String uri = resolveMetadataUri(request, resourceType);
        BigInteger price = requireNonNegative(request.price(), "price");
        String accessURI = requireText(request.accessURI(), "accessURI", 500);
        String accessKey = requireText(request.accessKey(), "accessKey", 200);
        validatePhysicalAccessKey(accessKey, resourceType);
        boolean listImmediately = request.listImmediately() == null || request.listImmediately();
        boolean allowDuplicate = Boolean.TRUE.equals(request.allowDuplicate());

        if (listImmediately || isQuickSetup(request)) {
            preflightMetadataUri(uri, wallet, resourceType);
        }

        List<BigInteger> before = walletService.getLabsOwnedByProvider(wallet);
        if (!allowDuplicate) {
            Optional<BigInteger> existingLab = findOwnedLabByUri(uri, before);
            if (existingLab.isPresent()) {
                return existingLabResponse(existingLab.get(), uri);
            }
        }

        Diamond diamond = loadWritableDiamond(operationKey("publish", "request", commandKey));
        TransactionReceipt receipt = listImmediately
            ? diamond.addAndListLabWithPucHash(uri, price, accessURI, accessKey, resourceType, creatorPucHash).send()
            : diamond.addLabWithPucHash(uri, price, accessURI, accessKey, resourceType, creatorPucHash).send();
        if (receipt == null || !receipt.isStatusOK()) {
            throw new IllegalStateException("Lab publication transaction was reverted");
        }
        BigInteger labId = extractCreatedLabId(receipt, wallet);

        return new LabAdminTransactionResponse(
            true,
            listImmediately ? "addAndListLabWithPucHash" : "addLabWithPucHash",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            uri
        );
    }

    public LabAdminTransactionResponse update(BigInteger labId, LabAdminPublishRequest request) throws Exception {
        return update(labId, request, null);
    }

    public LabAdminTransactionResponse update(
        BigInteger labId, LabAdminPublishRequest request, String idempotencyKey
    ) throws Exception {
        requireOwnedLab(labId);
        BigInteger resourceType = normalizeResourceType(request.resourceType());
        String uri = resolveMetadataUri(request, resourceType);
        BigInteger price = requireNonNegative(request.price(), "price");
        String accessURI = requireText(request.accessURI(), "accessURI", 500);
        String accessKey = requireText(request.accessKey(), "accessKey", 200);
        validatePhysicalAccessKey(accessKey, resourceType);
        if (isQuickSetup(request)) {
            preflightMetadataUri(uri, requireProviderWallet(), resourceType);
        }

        try {
            Diamond.Lab current = loadReadonlyDiamond().getLab(labId).send();
            if (isOnChainLabUnchanged(current.base, uri, price, accessURI, accessKey, resourceType)) {
                return new LabAdminTransactionResponse(
                    true,
                    "metadataOnly",
                    null,
                    "offchain_updated",
                    labId,
                    uri
                );
            }
        } catch (Exception ex) {
            log.debug("Unable to compare current on-chain lab state for lab {}; proceeding with updateLab", labId, ex);
        }

        TransactionReceipt receipt = loadWritableDiamond(operationKey("update", labId, idempotencyKey))
            .updateLab(labId, uri, price, accessURI, accessKey, resourceType)
            .send();
        requireSuccessfulReceipt(receipt, "Lab update");
        return new LabAdminTransactionResponse(
            true,
            "updateLab",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            uri
        );
    }

    public LabAdminTransactionResponse deleteLab(BigInteger labId) throws Exception {
        return deleteLab(labId, null);
    }

    public LabAdminTransactionResponse deleteLab(BigInteger labId, String idempotencyKey) throws Exception {
        requireOwnedLab(labId);
        String uri = walletService.getLabTokenUri(labId).orElse(null);
        String operationKey = operationKey("delete", labId, idempotencyKey);
        // Reserve the content hand-off before broadcasting. If this durable
        // write is unavailable, do not create an on-chain deletion that the
        // content service cannot safely reconcile after a crash.
        contentRetentionService.prepareDeletion(labId, uri, operationKey);
        TransactionReceipt receipt;
        try {
            receipt = loadWritableDiamond(operationKey).deleteLab(labId).send();
        } catch (Exception ex) {
            // A timeout or RPC failure is not evidence of a revert. Preserve
            // the durable block and let the reconciler inspect the tx outbox.
            contentRetentionService.markBroadcastUnknown(labId, operationKey, ex.getMessage());
            throw ex;
        }
        if (receipt == null) {
            contentRetentionService.markBroadcastUnknown(labId, operationKey, "Lab deletion transaction returned no receipt");
            throw new IllegalStateException("Lab deletion transaction returned no receipt");
        }
        if (!receipt.isStatusOK()) {
            contentRetentionService.cancelPreparedDeletion(labId);
            throw new IllegalStateException("Lab deletion transaction was reverted");
        }
        try {
            contentRetentionService.completeDeletion(labId, uri, receipt.getTransactionHash());
        } catch (IOException ex) {
            // The durable reservation and LabDeleted event handler keep the
            // content unavailable while the worker retries this hand-off.
            log.error("Lab {} deleted on-chain but content tombstone could not be written: {}", labId, ex.getMessage(), ex);
        }
        return new LabAdminTransactionResponse(
            true,
            "deleteLab",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            uri
        );
    }

    public LabAdminTransactionResponse listLab(BigInteger labId, boolean listed) throws Exception {
        return listLab(labId, listed, null);
    }

    public LabAdminTransactionResponse listLab(
        BigInteger labId, boolean listed, String idempotencyKey
    ) throws Exception {
        requireOwnedLab(labId);
        String uri = walletService.getLabTokenUri(labId).orElse(null);
        if (listed) {
            preflightMetadataUri(uri, requireProviderWallet(), resolveOnChainResourceType(labId));
        }
        TransactionReceipt receipt = listed
            ? loadWritableDiamond(operationKey("list", labId, idempotencyKey)).listLab(labId).send()
            : loadWritableDiamond(operationKey("unlist", labId, idempotencyKey)).unlistLab(labId).send();
        requireSuccessfulReceipt(receipt, listed ? "Lab list" : "Lab unlist");
        return new LabAdminTransactionResponse(
            true,
            listed ? "listLab" : "unlistLab",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            uri
        );
    }

    private void preflightMetadataUri(
        String metadataUri,
        String providerAddress,
        BigInteger resourceType
    ) throws IOException {
        String uri = requireText(metadataUri, "metadataUri", 1000);
        String gatewayPrefix = publicBaseUrl().replaceAll("/+$", "") + "/lab-content/";
        if (uri.startsWith(gatewayPrefix)) {
            String relativePath = uri.substring(gatewayPrefix.length());
            Path metadataFile = contentRoot().resolve(relativePath).normalize();
            ensureWithinContentRoot(metadataFile);
            if (!Files.isRegularFile(metadataFile) || Files.size(metadataFile) > 1024L * 1024L) {
                throw new IllegalArgumentException("Metadata preflight failed: document is unavailable");
            }
            try {
                Map<String, Object> metadata = objectMapper.readValue(
                    metadataFile.toFile(), new TypeReference<Map<String, Object>>() {}
                );
                normalizeGeneratedMetadata(metadata);
                validateGeneratedMetadata(metadata);
                validateGeneratedMetadataCapacity(metadata, resourceType);
            } catch (IllegalArgumentException ex) {
                throw ex;
            } catch (Exception ex) {
                throw new IllegalArgumentException("Metadata preflight failed: document is not valid JSON", ex);
            }
            return;
        }

        try {
            LabMetadata metadata = resourceType == null
                ? labMetadataService.getLabMetadataForProvider(providerAddress, uri)
                : labMetadataService.getLabMetadataForProvider(providerAddress, uri, resourceType);
            if (BigInteger.ONE.equals(resourceType)) {
                stationCapacityService.validateDeclaredCapacity(metadata.getMaxConcurrentUsers());
            }
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Metadata preflight failed: URI is not accessible", ex);
        }
    }

    private TransactionReceipt requireSuccessfulReceipt(TransactionReceipt receipt, String operation) {
        if (receipt == null || !receipt.isStatusOK()) {
            throw new IllegalStateException(operation + " transaction was reverted");
        }
        return receipt;
    }

    private BigInteger resolveOnChainResourceType(BigInteger labId) throws Exception {
        Diamond.Lab lab = loadReadonlyDiamond().getLab(labId).send();
        if (lab == null || lab.base == null || lab.base.resourceType == null) {
            throw new IllegalStateException("On-chain resource type is unavailable for lab " + labId);
        }
        return lab.base.resourceType;
    }

    public org.springframework.core.io.Resource loadContentResource(String relativePath) throws IOException {
        contentRetentionService.assertAvailable(relativePath);
        Path target = contentRoot().resolve(relativePath).normalize();
        ensureWithinContentRoot(target);
        if (!Files.isRegularFile(target)) {
            throw new java.io.FileNotFoundException("Content not found");
        }
        return new org.springframework.core.io.UrlResource(target.toUri());
    }

    public String contentTypeFor(String relativePath) {
        try {
            Path target = contentRoot().resolve(relativePath).normalize();
            ensureWithinContentRoot(target);
            String detected = Files.probeContentType(target);
            return detected != null ? detected : MediaType.APPLICATION_OCTET_STREAM_VALUE;
        } catch (Exception ignored) {
            log.debug("Unable to detect content type for requested lab content");
            return MediaType.APPLICATION_OCTET_STREAM_VALUE;
        }
    }

    private String resolveMetadataUri(LabAdminPublishRequest request, BigInteger resourceType) throws IOException {
        String setupMode = setupMode(request);
        if ("quick".equals(setupMode)) {
            return requireHttpsUrl(request.metadataUrl(), "metadataUrl");
        }

        Map<String, Object> metadata = request.metadata() == null
            ? new LinkedHashMap<>()
            : new LinkedHashMap<>(request.metadata());
        normalizeGeneratedMetadata(metadata);
        validateGeneratedMetadata(metadata);
        validateGeneratedMetadataCapacity(metadata, resourceType);
        String contentId = normalizeContentId(objectsToString(metadata.get("contentId")));
        metadata.remove("contentId");
        Path targetDir = contentRoot().resolve("content").resolve(contentId).normalize();
        ensureWithinContentRoot(targetDir);
        Files.createDirectories(targetDir);
        Path metadataFile = targetDir.resolve("metadata.json").normalize();
        ensureWithinContentRoot(metadataFile);
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(metadataFile.toFile(), metadata);
        return publicBaseUrl() + "/lab-content/content/" + contentId + "/metadata.json";
    }

    private boolean isQuickSetup(LabAdminPublishRequest request) {
        return "quick".equals(setupMode(request));
    }

    private String setupMode(LabAdminPublishRequest request) {
        return Optional.ofNullable(request.setupMode()).orElse("full").trim().toLowerCase(Locale.ROOT);
    }

    private void validateGeneratedMetadata(Map<String, Object> metadata) {
        requireMetadataText(metadata, "name", 160);
        requireMetadataText(metadata, "description", 4000);
        Object image = metadata.get("image");
        if (image != null && !objectsToString(image).isBlank()) {
            requireHttpsOrGatewayUrl(objectsToString(image), "image");
        }
        for (String url : stringList(metadata.get("images"))) {
            requireHttpsOrGatewayUrl(url, "images");
        }
        for (String url : stringList(metadata.get("docs"))) {
            requireHttpsOrGatewayUrl(url, "docs");
        }
    }

    private void validateGeneratedMetadataCapacity(Map<String, Object> metadata, BigInteger resourceType) {
        if (!BigInteger.ONE.equals(resourceType)) {
            return;
        }
        stationCapacityService.validateDeclaredCapacity(extractMaxConcurrentUsers(metadata));
    }

    private Integer extractMaxConcurrentUsers(Map<String, Object> metadata) {
        Object direct = metadata.get("maxConcurrentUsers");
        if (direct instanceof Number number) {
            return number.intValue();
        }
        for (Map<String, Object> attribute : metadataAttributes(metadata.get("attributes"))) {
            if (!"maxConcurrentUsers".equalsIgnoreCase(objectsToString(attribute.get("trait_type")))) {
                continue;
            }
            Object value = attribute.get("value");
            if (value instanceof Number number) {
                return number.intValue();
            }
            try {
                return Integer.valueOf(objectsToString(value));
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private void requireMetadataText(Map<String, Object> metadata, String field, int max) {
        String value = objectsToString(metadata.get(field));
        if (value.isBlank() || value.length() > max) {
            throw new IllegalArgumentException("metadata." + field + " is required and must be under " + max + " characters");
        }
    }

    private String requireHttpsUrl(String value, String field) {
        String text = requireText(value, field, 1000);
        if (!text.startsWith("https://") && !text.startsWith(publicBaseUrl() + "/")) {
            throw new IllegalArgumentException(field + " must be an HTTPS URL");
        }
        return text;
    }

    private void requireHttpsOrGatewayUrl(String value, String field) {
        if (!value.startsWith("https://") && !value.startsWith(publicBaseUrl() + "/")) {
            throw new IllegalArgumentException("metadata." + field + " must be an HTTPS URL");
        }
    }

    BigInteger extractCreatedLabId(TransactionReceipt receipt, String providerWallet) {
        if (receipt == null || receipt.getLogs() == null) {
            throw new IllegalStateException("Successful lab publication has no receipt logs");
        }
        String expectedProviderTopic = indexedAddressTopic(providerWallet);
        for (Log logEntry : receipt.getLogs()) {
            if (logEntry == null || !isContractLog(logEntry) || logEntry.getTopics() == null) {
                continue;
            }
            List<String> topics = logEntry.getTopics();
            if (topics.size() < 4 || !ERC721_TRANSFER_TOPIC.equalsIgnoreCase(topics.get(0))) {
                continue;
            }
            if (!BigInteger.ZERO.equals(Numeric.toBigInt(topics.get(1)))) {
                continue;
            }
            if (!expectedProviderTopic.equalsIgnoreCase(topics.get(2))) {
                continue;
            }
            BigInteger tokenId = Numeric.toBigInt(topics.get(3));
            if (tokenId != null) {
                return tokenId;
            }
        }
        throw new IllegalStateException("Successful lab publication has no mint Transfer event for the provider wallet");
    }

    private boolean isContractLog(Log logEntry) {
        return logEntry.getAddress() == null
            || contractAddress == null
            || contractAddress.isBlank()
            || contractAddress.equalsIgnoreCase(logEntry.getAddress());
    }

    private String indexedAddressTopic(String address) {
        String normalized = Numeric.cleanHexPrefix(address == null ? "" : address).toLowerCase(Locale.ROOT);
        if (!normalized.matches("[0-9a-f]{40}")) {
            throw new IllegalArgumentException("provider wallet must be a valid address");
        }
        return "0x" + "0".repeat(24) + normalized;
    }

    Optional<BigInteger> findOwnedLabByUri(String uri, List<BigInteger> ownedLabs) {
        if (uri == null || uri.isBlank() || ownedLabs == null || ownedLabs.isEmpty()) {
            return Optional.empty();
        }
        return ownedLabs.stream()
            .filter(labId -> walletService.getLabTokenUri(labId)
                .map(existingUri -> existingUri.equalsIgnoreCase(uri))
                .orElse(false))
            .findFirst();
    }

    boolean isOnChainLabUnchanged(
        Diamond.LabBase current,
        String uri,
        BigInteger price,
        String accessURI,
        String accessKey,
        BigInteger resourceType
    ) {
        if (current == null) {
            return false;
        }
        return Objects.equals(current.uri, uri)
            && Objects.equals(current.price, price)
            && Objects.equals(current.accessURI, accessURI)
            && Objects.equals(current.accessKey, accessKey)
            && Objects.equals(current.resourceType, resourceType);
    }

    private LabAdminTransactionResponse existingLabResponse(BigInteger labId, String uri) {
        return new LabAdminTransactionResponse(
            true,
            "existingLab",
            null,
            "already_exists",
            labId,
            uri
        );
    }

    private String requirePublishIdempotencyKey(String idempotencyKey) {
        String normalized = idempotencyKey == null ? "" : idempotencyKey.trim();
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Idempotency-Key is required for lab publication");
        }
        if (normalized.length() > 128) {
            throw new IllegalArgumentException("Idempotency-Key must not exceed 128 characters");
        }
        return normalized;
    }

    private String resolveCreatorPucHash(LabAdminPublishRequest request) {
        String requested = request == null ? null : request.creatorPucHash();
        return requireCreatorPucHash(hasText(requested) ? requested : configuredCreatorPucHash);
    }

    private String requireCreatorPucHash(String value) {
        String normalized = value == null ? "" : value.trim();
        if (!BYTES32_PATTERN.matcher(normalized).matches() || ZERO_BYTES32.equalsIgnoreCase(normalized)) {
            throw new IllegalArgumentException("creatorPucHash must be a non-zero 0x-prefixed bytes32 value");
        }
        return normalized.toLowerCase(Locale.ROOT);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String operationKey(String action, Object businessId, String idempotencyKey) {
        String instance = idempotencyKey == null ? "" : idempotencyKey.trim();
        if (instance.isBlank()) {
            instance = UUID.randomUUID().toString();
        }
        return "lab-admin:" + action + ":" + String.valueOf(businessId) + ":" + instance;
    }

    private String requireProviderWallet() {
        if (!institutionalWalletService.isConfigured()) {
            throw new IllegalStateException("Institutional wallet is not configured");
        }
        String wallet = institutionalWalletService.getInstitutionalWalletAddress();
        if (!walletService.isLabProvider(wallet)) {
            throw new IllegalStateException("Institutional wallet is not registered as a lab provider");
        }
        return wallet;
    }

    private void requireOwnedLab(BigInteger labId) {
        if (labId == null || labId.compareTo(BigInteger.ZERO) <= 0) {
            throw new IllegalArgumentException("labId must be greater than zero");
        }
        String wallet = requireProviderWallet();
        if (!walletService.isLabOwnedByProvider(wallet, labId)) {
            throw new IllegalArgumentException("Lab is not owned by this provider wallet");
        }
    }

    Diamond loadReadonlyDiamond() {
        Web3j currentWeb3j = walletService.getWeb3jInstance();
        return Diamond.load(
            contractAddress,
            currentWeb3j,
            new org.web3j.tx.ReadonlyTransactionManager(currentWeb3j, contractAddress),
            new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );
    }

    Diamond loadWritableDiamond(String operationKey) {
        Web3j currentWeb3j = walletService.getWeb3jInstance();
        TransactionManager txManager = txManagerProvider.get(currentWeb3j, operationKey);
        return Diamond.load(
            contractAddress,
            currentWeb3j,
            txManager,
            new StaticGasProvider(resolveGasPriceWei(currentWeb3j), contractGasLimit)
        );
    }

    private BigInteger resolveGasPriceWei(Web3j currentWeb3j) {
        BigInteger fallback = Convert.toWei(
            Optional.ofNullable(defaultGasPriceGwei).orElse(BigInteger.ONE).toString(),
            Convert.Unit.GWEI
        ).toBigInteger();
        String strategy = Optional.ofNullable(gasPriceStrategy).orElse("network").trim().toLowerCase(Locale.ROOT);
        if ("fixed".equals(strategy)) {
            return fallback;
        }
        if (!"network".equals(strategy)) {
            log.warn("Unknown ethereum.gas.price.strategy '{}'; using network gas price with configured fallback", strategy);
        }
        try {
            var response = currentWeb3j.ethGasPrice().send();
            return response != null && response.getGasPrice() != null ? response.getGasPrice() : fallback;
        } catch (Exception ex) {
            log.warn("Unable to resolve gas price, using default: {}", LogSanitizer.sanitize(ex.getMessage()));
            return fallback;
        }
    }

    private List<Map<String, Object>> listFmus() {
        Path base = Path.of(fmuDataPath).normalize();
        if (!Files.isDirectory(base)) {
            return List.of();
        }
        List<Map<String, Object>> result = new ArrayList<>();
        try (var stream = Files.walk(base, 3)) {
            stream
                .filter(Files::isRegularFile)
                .filter(path -> path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".fmu"))
                .limit(200)
                .forEach(path -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("fileName", path.getFileName().toString());
                    item.put("relativePath", base.relativize(path).toString().replace('\\', '/'));
                    try {
                        item.put("size", Files.size(path));
                    } catch (IOException ignored) {
                        log.debug("Unable to determine file size for {}", path, ignored);
                        item.put("size", null);
                    }
                    result.add(item);
                });
        } catch (IOException ex) {
            log.warn("Unable to list FMU data path {}: {}", fmuDataPath, LogSanitizer.sanitize(ex.getMessage()));
        }
        return result;
    }

    private String publicBaseUrl() {
        return backendUrlResolver.resolveBaseDomain();
    }

    private Path contentRoot() throws IOException {
        Path root = Path.of(contentBasePath).toAbsolutePath().normalize();
        Files.createDirectories(root);
        return root;
    }

    private void ensureWithinContentRoot(Path path) throws IOException {
        if (!path.toAbsolutePath().normalize().startsWith(contentRoot())) {
            throw new IllegalArgumentException("Invalid content path");
        }
    }

    private String normalizeContentId(String value) {
        String text = value == null ? "" : value.trim();
        if (text.isBlank()) {
            return UUID.randomUUID().toString();
        }
        if (!text.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,80}")) {
            throw new IllegalArgumentException("Invalid contentId");
        }
        return text;
    }

    private String normalizeAssetKind(String value) {
        String text = Optional.ofNullable(value).orElse("").trim().toLowerCase(Locale.ROOT);
        if ("image".equals(text)) return "images";
        if ("doc".equals(text) || "document".equals(text)) return "docs";
        if (!"images".equals(text) && !"docs".equals(text)) {
            throw new IllegalArgumentException("Asset kind must be images or docs");
        }
        return text;
    }

    private String normalizeUploadedAssetPath(String value) {
        String text = Optional.ofNullable(value).orElse("").trim();
        if (text.isBlank()) {
            throw new IllegalArgumentException("Asset path is required");
        }
        if (text.startsWith("http://") || text.startsWith("https://")) {
            try {
                text = URI.create(text).getPath();
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Invalid asset path", ex);
            }
        }
        if (text.startsWith("/lab-content/")) {
            text = text.substring("/lab-content/".length());
        } else if (text.startsWith("lab-content/")) {
            text = text.substring("lab-content/".length());
        }
        while (text.startsWith("/")) {
            text = text.substring(1);
        }
        Path normalized = Path.of(text).normalize();
        if (normalized.isAbsolute() || normalized.startsWith("..")) {
            throw new IllegalArgumentException("Invalid asset path");
        }
        if (!"content".equals(normalized.getName(0).toString())) {
            throw new IllegalArgumentException("Invalid asset path");
        }
        if (normalized.getNameCount() == 3 && "metadata.json".equals(normalized.getName(2).toString())) {
            throw new IllegalArgumentException("Only uploaded image and document assets can be deleted");
        }
        if (normalized.getNameCount() < 4) {
            throw new IllegalArgumentException("Invalid asset path");
        }
        String kind = normalized.getName(2).toString();
        if (!"images".equals(kind) && !"docs".equals(kind)) {
            throw new IllegalArgumentException("Only uploaded image and document assets can be deleted");
        }
        if (normalized.getNameCount() != 4) {
            throw new IllegalArgumentException("Invalid asset path");
        }
        return normalized.toString().replace('\\', '/');
    }

    private String safeFileName(String original, String contentType, String kind) {
        String fallback = "images".equals(kind) ? "asset" : "document";
        String base = Optional.ofNullable(original).orElse(fallback).replace('\\', '/');
        int slash = base.lastIndexOf('/');
        if (slash >= 0) base = base.substring(slash + 1);
        base = base.replaceAll("[^A-Za-z0-9._-]", "_");
        if (base.isBlank() || ".".equals(base) || "..".equals(base)) {
            base = fallback;
        }
        if (!base.contains(".")) {
            base += switch (contentType) {
                case "image/png" -> ".png";
                case "image/webp" -> ".webp";
                case "image/gif" -> ".gif";
                case "application/pdf" -> ".pdf";
                default -> ".jpg";
            };
        }
        return UUID.randomUUID() + "-" + base;
    }

    private String requireText(String value, String field, int max) {
        if (!StringUtils.hasText(value) || value.trim().length() > max) {
            throw new IllegalArgumentException(field + " is required and must be under " + max + " characters");
        }
        return value.trim();
    }

    private BigInteger requireNonNegative(BigInteger value, String field) {
        if (value == null || value.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException(field + " must be a non-negative integer");
        }
        BigInteger maxUint96 = BigInteger.ONE.shiftLeft(96).subtract(BigInteger.ONE);
        if (value.compareTo(maxUint96) > 0) {
            throw new IllegalArgumentException(field + " exceeds uint96");
        }
        return value;
    }

    private BigInteger normalizeResourceType(Integer value) {
        int type = value == null ? 0 : value;
        if (type < 0 || type > 1) {
            throw new IllegalArgumentException("resourceType must be 0 or 1");
        }
        return BigInteger.valueOf(type);
    }

    private void validatePhysicalAccessKey(String accessKey, BigInteger resourceType) {
        if (BigInteger.ONE.equals(resourceType)) {
            return;
        }
        GuacamoleProvisioningService.parseConnectionId(accessKey);
    }

    private String objectsToString(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    void normalizeGeneratedMetadata(Map<String, Object> metadata) {
        String primaryImage = objectsToString(metadata.get("image"));
        List<String> images = new ArrayList<>();
        addDistinct(images, primaryImage);

        List<Map<String, Object>> attributes = metadataAttributes(metadata.get("attributes"));
        List<String> additionalImages = new ArrayList<>();

        for (Map<String, Object> attribute : attributes) {
            String traitType = objectsToString(attribute.get("trait_type"));
            if ("additionalImages".equals(traitType)) {
                addDistinct(additionalImages, stringList(attribute.get("value")));
            }
        }

        addDistinct(images, additionalImages);

        if (primaryImage.isBlank() && !images.isEmpty()) {
            metadata.put("image", images.get(0));
        }
    }

    private void addDistinct(List<String> target, List<String> values) {
        for (String value : values) {
            addDistinct(target, value);
        }
    }

    private void addDistinct(List<String> target, String value) {
        String text = objectsToString(value);
        if (!text.isBlank() && target.stream().noneMatch(text::equals)) {
            target.add(text);
        }
    }

    private List<Map<String, Object>> metadataAttributes(Object value) {
        if (!(value instanceof List<?> values)) {
            return List.of();
        }
        List<Map<String, Object>> attributes = new ArrayList<>();
        for (Object item : values) {
            if (item instanceof Map<?, ?> map) {
                Map<String, Object> normalized = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    normalized.put(String.valueOf(entry.getKey()), entry.getValue());
                }
                attributes.add(normalized);
            }
        }
        return attributes;
    }

    private List<String> stringList(Object value) {
        List<String> result = new ArrayList<>();
        if (value instanceof List<?> values) {
            for (Object item : values) {
                String text = objectsToString(item);
                if (!text.isBlank()) {
                    result.add(text);
                }
            }
            return result;
        }
        String text = objectsToString(value);
        if (!text.isBlank()) {
            result.add(text);
        }
        return result;
    }
}
