package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.CreditUnitConverter;
import decentralabs.blockchain.util.LogSanitizer;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Event;
import org.web3j.abi.datatypes.Int;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Int256;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.core.methods.response.EthLog;
import org.web3j.protocol.core.methods.response.EthTransaction;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.protocol.core.methods.response.Transaction;
import org.web3j.utils.Numeric;

@Service
@RequiredArgsConstructor
@Slf4j
public class OnChainAdminTransactionService {

    private static final int LAB_TOKEN_DECIMALS = CreditUnitConverter.CREDIT_DECIMALS;

    private static final Event PROVIDER_PAYOUT_REQUESTED_EVENT = new Event(
        "ProviderPayoutRequested",
        List.of(
            new TypeReference<Address>(true) {},
            new TypeReference<Uint256>(true) {},
            new TypeReference<Uint256>() {},
            new TypeReference<Uint256>() {}
        )
    );

    private static final Event PROVIDER_RECEIVABLE_LIFECYCLE_TRANSITION_EVENT = new Event(
        "ProviderReceivableLifecycleTransition",
        List.of(
            new TypeReference<Address>(true) {},
            new TypeReference<Uint256>(true) {},
            new TypeReference<Uint256>(true) {},
            new TypeReference<Uint256>() {},
            new TypeReference<Uint256>() {},
            new TypeReference<Bytes32>() {}
        )
    );

    private static final Event BACKEND_AUTHORIZED_EVENT = new Event(
        "BackendAuthorized",
        List.of(
            new TypeReference<Address>(true) {},
            new TypeReference<Address>(true) {}
        )
    );

    private static final Event BACKEND_REVOKED_EVENT = new Event(
        "BackendRevoked",
        List.of(
            new TypeReference<Address>(true) {},
            new TypeReference<Address>(true) {}
        )
    );

    private static final Event INSTITUTIONAL_USER_LIMIT_UPDATED_EVENT = new Event(
        "InstitutionalUserLimitUpdated",
        List.of(
            new TypeReference<Address>(true) {},
            new TypeReference<Uint256>() {}
        )
    );

    private static final Event INSTITUTIONAL_SPENDING_PERIOD_UPDATED_EVENT = new Event(
        "InstitutionalSpendingPeriodUpdated",
        List.of(
            new TypeReference<Address>(true) {},
            new TypeReference<Uint256>() {}
        )
    );

    private static final Event INSTITUTIONAL_SPENDING_PERIOD_RESET_EVENT = new Event(
        "InstitutionalSpendingPeriodReset",
        List.of(
            new TypeReference<Address>(true) {},
            new TypeReference<Uint256>() {}
        )
    );

    private static final Event SERVICE_CREDIT_ISSUED_EVENT = new Event(
        "ServiceCreditIssued",
        List.of(
            new TypeReference<Address>(true) {},
            new TypeReference<Uint256>() {},
            new TypeReference<Uint256>() {},
            new TypeReference<Bytes32>(true) {}
        )
    );

    private static final Event SERVICE_CREDIT_ADJUSTED_EVENT = new Event(
        "ServiceCreditAdjusted",
        List.of(
            new TypeReference<Address>(true) {},
            new TypeReference<Int256>() {},
            new TypeReference<Uint256>() {},
            new TypeReference<Bytes32>(true) {}
        )
    );

    private final Web3j web3j;
    private final WalletService walletService;
    private final LabMetadataService labMetadataService;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${billing.admin.transactions.lookback-blocks:100000}")
    private int lookbackBlocks;

    @Value("${billing.admin.transactions.cache-ttl-ms:15000}")
    private long cacheTtlMs;

    @Value("${billing.admin.transactions.cache-max-per-provider:50}")
    private int cacheMaxPerProvider;

    private final ConcurrentMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public List<InstitutionalAnalyticsService.TransactionRecord> getRecentTransactions(String providerAddress, int limit) {
        String provider = normalizeAddress(providerAddress);
        if (provider.isBlank()) {
            return List.of();
        }

        int safeLimit = Math.max(1, Math.min(limit, Math.max(1, cacheMaxPerProvider)));
        String cacheKey = provider + "|" + normalizeAddress(contractAddress);
        long now = Instant.now().toEpochMilli();

        CacheEntry cached = cache.get(cacheKey);
        if (cached != null && (now - cached.cachedAtEpochMs) <= cacheTtlMs) {
            return cached.records.stream().limit(safeLimit).toList();
        }

        try {
            List<InstitutionalAnalyticsService.TransactionRecord> fresh = loadRecentTransactionsFromChain(provider, safeLimit);
            cache.put(cacheKey, new CacheEntry(now, fresh));
            return fresh;
        } catch (Exception ex) {
            log.warn("Failed to load on-chain admin transactions for {}: {}", provider, LogSanitizer.sanitize(ex.getMessage()));
            if (cached != null) {
                return cached.records.stream().limit(safeLimit).toList();
            }
            return List.of();
        }
    }

    private List<InstitutionalAnalyticsService.TransactionRecord> loadRecentTransactionsFromChain(
        String providerAddress,
        int limit
    ) throws Exception {
        BigInteger currentBlock = web3j.ethBlockNumber().send().getBlockNumber();
        BigInteger fromBlock = currentBlock.subtract(BigInteger.valueOf(Math.max(1, lookbackBlocks)));
        if (fromBlock.compareTo(BigInteger.ZERO) < 0) {
            fromBlock = BigInteger.ZERO;
        }

        List<OnChainEventRecord> candidates = new ArrayList<>();
        Map<String, Long> blockTimestampCache = new HashMap<>();
        Map<String, String> txFromCache = new HashMap<>();
        Map<String, String> labNameCache = new HashMap<>();

        candidates.addAll(fetchEventsForIndexedInstitution(
            providerAddress,
            fromBlock,
            currentBlock,
            BACKEND_AUTHORIZED_EVENT,
            this::mapBackendAuthorized,
            blockTimestampCache,
            txFromCache,
            labNameCache
        ));
        candidates.addAll(fetchEventsForIndexedInstitution(
            providerAddress,
            fromBlock,
            currentBlock,
            BACKEND_REVOKED_EVENT,
            this::mapBackendRevoked,
            blockTimestampCache,
            txFromCache,
            labNameCache
        ));
        candidates.addAll(fetchEventsForIndexedInstitution(
            providerAddress,
            fromBlock,
            currentBlock,
            INSTITUTIONAL_USER_LIMIT_UPDATED_EVENT,
            this::mapUserLimitUpdated,
            blockTimestampCache,
            txFromCache,
            labNameCache
        ));
        candidates.addAll(fetchEventsForIndexedInstitution(
            providerAddress,
            fromBlock,
            currentBlock,
            INSTITUTIONAL_SPENDING_PERIOD_UPDATED_EVENT,
            this::mapSpendingPeriodUpdated,
            blockTimestampCache,
            txFromCache,
            labNameCache
        ));
        candidates.addAll(fetchEventsForIndexedInstitution(
            providerAddress,
            fromBlock,
            currentBlock,
            INSTITUTIONAL_SPENDING_PERIOD_RESET_EVENT,
            this::mapSpendingPeriodReset,
            blockTimestampCache,
            txFromCache,
            labNameCache
        ));
        candidates.addAll(fetchEventsForIndexedProvider(
            providerAddress,
            fromBlock,
            currentBlock,
            PROVIDER_PAYOUT_REQUESTED_EVENT,
            this::mapProviderPayoutRequested,
            blockTimestampCache,
            txFromCache,
            labNameCache
        ));
        candidates.addAll(fetchEventsForIndexedOperator(
            providerAddress,
            fromBlock,
            currentBlock,
            PROVIDER_RECEIVABLE_LIFECYCLE_TRANSITION_EVENT,
            this::mapReceivableTransition,
            blockTimestampCache,
            txFromCache,
            labNameCache
        ));
        candidates.addAll(fetchEventsBySender(
            providerAddress,
            fromBlock,
            currentBlock,
            SERVICE_CREDIT_ISSUED_EVENT,
            this::mapServiceCreditIssued,
            blockTimestampCache,
            txFromCache,
            labNameCache
        ));
        candidates.addAll(fetchEventsBySender(
            providerAddress,
            fromBlock,
            currentBlock,
            SERVICE_CREDIT_ADJUSTED_EVENT,
            this::mapServiceCreditAdjusted,
            blockTimestampCache,
            txFromCache,
            labNameCache
        ));

        Map<String, OnChainEventRecord> deduped = new LinkedHashMap<>();
        for (OnChainEventRecord candidate : candidates) {
            deduped.merge(candidate.hash, candidate, this::preferHigherPriorityRecord);
        }

        return deduped.values().stream()
            .sorted(
                Comparator.comparing(OnChainEventRecord::blockNumber, Comparator.reverseOrder())
                    .thenComparing(OnChainEventRecord::logIndex, Comparator.reverseOrder())
            )
            .limit(limit)
            .map(record -> new InstitutionalAnalyticsService.TransactionRecord(
                record.hash,
                record.type,
                record.description,
                record.amountTokens,
                record.timestamp,
                "confirmed"
            ))
            .toList();
    }

    private Collection<OnChainEventRecord> fetchEventsForIndexedInstitution(
        String institutionAddress,
        BigInteger fromBlock,
        BigInteger toBlock,
        Event event,
        EventMapper mapper,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) throws Exception {
        EthFilter filter = baseFilter(fromBlock, toBlock, event);
        filter.addOptionalTopics(paddedAddressTopic(institutionAddress));
        return mapLogs(filter, event, mapper, blockTimestampCache, txFromCache, labNameCache);
    }

    private Collection<OnChainEventRecord> fetchEventsForIndexedProvider(
        String providerAddress,
        BigInteger fromBlock,
        BigInteger toBlock,
        Event event,
        EventMapper mapper,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) throws Exception {
        return fetchEventsForIndexedInstitution(
            providerAddress,
            fromBlock,
            toBlock,
            event,
            mapper,
            blockTimestampCache,
            txFromCache,
            labNameCache
        );
    }

    private Collection<OnChainEventRecord> fetchEventsForIndexedOperator(
        String operatorAddress,
        BigInteger fromBlock,
        BigInteger toBlock,
        Event event,
        EventMapper mapper,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) throws Exception {
        return fetchEventsForIndexedInstitution(
            operatorAddress,
            fromBlock,
            toBlock,
            event,
            mapper,
            blockTimestampCache,
            txFromCache,
            labNameCache
        );
    }

    private Collection<OnChainEventRecord> fetchEventsBySender(
        String senderAddress,
        BigInteger fromBlock,
        BigInteger toBlock,
        Event event,
        EventMapper mapper,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) throws Exception {
        EthFilter filter = baseFilter(fromBlock, toBlock, event);
        List<OnChainEventRecord> records = new ArrayList<>();
        for (Log logEntry : getLogs(filter)) {
            String txSender = getTransactionSender(logEntry.getTransactionHash(), txFromCache);
            if (!normalizeAddress(txSender).equals(senderAddress)) {
                continue;
            }
            Optional<OnChainEventRecord> mapped = mapper.map(logEntry, event, blockTimestampCache, txFromCache, labNameCache);
            mapped.ifPresent(records::add);
        }
        return records;
    }

    private Collection<OnChainEventRecord> mapLogs(
        EthFilter filter,
        Event event,
        EventMapper mapper,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) throws Exception {
        List<OnChainEventRecord> records = new ArrayList<>();
        for (Log logEntry : getLogs(filter)) {
            Optional<OnChainEventRecord> mapped = mapper.map(logEntry, event, blockTimestampCache, txFromCache, labNameCache);
            mapped.ifPresent(records::add);
        }
        return records;
    }

    private List<Log> getLogs(EthFilter filter) throws Exception {
        EthLog ethLog = web3j.ethGetLogs(filter).send();
        if (ethLog.hasError()) {
            throw new IllegalStateException("eth_getLogs failed: " + ethLog.getError().getMessage());
        }

        @SuppressWarnings("unchecked")
        List<EthLog.LogResult<?>> rawLogs = (List<EthLog.LogResult<?>>) (List<?>) ethLog.getLogs();
        List<Log> logs = new ArrayList<>();
        for (EthLog.LogResult<?> rawLog : rawLogs) {
            if (rawLog instanceof EthLog.LogObject logObject) {
                logs.add(logObject.get());
            }
        }
        return logs;
    }

    private EthFilter baseFilter(BigInteger fromBlock, BigInteger toBlock, Event event) {
        EthFilter filter = new EthFilter(
            DefaultBlockParameter.valueOf(fromBlock),
            DefaultBlockParameter.valueOf(toBlock),
            contractAddress
        );
        filter.addSingleTopic(EventEncoder.encode(event));
        return filter;
    }

    private Optional<OnChainEventRecord> mapProviderPayoutRequested(
        Log logEntry,
        Event event,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) {
        List<Type> decoded = decodeNonIndexed(logEntry, event);
        if (decoded.size() < 2) {
            return Optional.empty();
        }

        BigInteger labId = decodeUint256Topic(logEntry.getTopics(), 2);
        BigInteger amount = asBigInteger(decoded.get(0));
        BigInteger processedReservations = asBigInteger(decoded.get(1));
        String labName = resolveLabDisplayName(labId, labNameCache);

        return Optional.of(buildRecord(
            logEntry,
            "COLLECT_LAB_PAYOUT",
            "Request provider payout for " + labName + " (" + processedReservations + " reservations processed)",
            formatCredits(amount),
            100,
            blockTimestampCache
        ));
    }

    private Optional<OnChainEventRecord> mapReceivableTransition(
        Log logEntry,
        Event event,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) {
        List<Type> decoded = decodeNonIndexed(logEntry, event);
        if (decoded.size() < 3) {
            return Optional.empty();
        }

        BigInteger labId = decodeUint256Topic(logEntry.getTopics(), 2);
        BigInteger fromState = decodeUint256Topic(logEntry.getTopics(), 3);
        BigInteger toState = asBigInteger(decoded.get(0));
        BigInteger amount = asBigInteger(decoded.get(1));
        String labName = resolveLabDisplayName(labId, labNameCache);

        return Optional.of(buildRecord(
            logEntry,
            "TRANSITION_PROVIDER_RECEIVABLE_STATE",
            "Transition provider receivable for " + labName + " from "
                + receivableStateLabel(fromState) + " to " + receivableStateLabel(toState),
            formatCredits(amount),
            20,
            blockTimestampCache
        ));
    }

    private Optional<OnChainEventRecord> mapBackendAuthorized(
        Log logEntry,
        Event event,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) {
        String backendAddress = decodeAddressTopic(logEntry.getTopics(), 2);
        return Optional.of(buildRecord(
            logEntry,
            "AUTHORIZE_BACKEND",
            "Authorized backend " + backendAddress,
            null,
            80,
            blockTimestampCache
        ));
    }

    private Optional<OnChainEventRecord> mapBackendRevoked(
        Log logEntry,
        Event event,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) {
        String backendAddress = decodeAddressTopic(logEntry.getTopics(), 2);
        return Optional.of(buildRecord(
            logEntry,
            "REVOKE_BACKEND",
            "Revoked backend " + backendAddress,
            null,
            80,
            blockTimestampCache
        ));
    }

    private Optional<OnChainEventRecord> mapUserLimitUpdated(
        Log logEntry,
        Event event,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) {
        List<Type> decoded = decodeNonIndexed(logEntry, event);
        if (decoded.isEmpty()) {
            return Optional.empty();
        }
        BigInteger newLimit = asBigInteger(decoded.get(0));
        return Optional.of(buildRecord(
            logEntry,
            "SET_USER_LIMIT",
            "Updated institutional user limit",
            formatCredits(newLimit),
            70,
            blockTimestampCache
        ));
    }

    private Optional<OnChainEventRecord> mapSpendingPeriodUpdated(
        Log logEntry,
        Event event,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) {
        List<Type> decoded = decodeNonIndexed(logEntry, event);
        if (decoded.isEmpty()) {
            return Optional.empty();
        }
        BigInteger newPeriod = asBigInteger(decoded.get(0));
        return Optional.of(buildRecord(
            logEntry,
            "SET_SPENDING_PERIOD",
            "Updated institutional spending period",
            formatPeriodDays(newPeriod),
            70,
            blockTimestampCache
        ));
    }

    private Optional<OnChainEventRecord> mapSpendingPeriodReset(
        Log logEntry,
        Event event,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) {
        return Optional.of(buildRecord(
            logEntry,
            "RESET_SPENDING_PERIOD",
            "Reset institutional spending period anchor",
            null,
            70,
            blockTimestampCache
        ));
    }

    private Optional<OnChainEventRecord> mapServiceCreditIssued(
        Log logEntry,
        Event event,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) {
        List<Type> decoded = decodeNonIndexed(logEntry, event);
        if (decoded.size() < 2) {
            return Optional.empty();
        }

        String account = decodeAddressTopic(logEntry.getTopics(), 1);
        BigInteger amount = asBigInteger(decoded.get(0));
        return Optional.of(buildRecord(
            logEntry,
            "ISSUE_SERVICE_CREDITS",
            "Issued service credits to " + account,
            formatCredits(amount),
            60,
            blockTimestampCache
        ));
    }

    private Optional<OnChainEventRecord> mapServiceCreditAdjusted(
        Log logEntry,
        Event event,
        Map<String, Long> blockTimestampCache,
        Map<String, String> txFromCache,
        Map<String, String> labNameCache
    ) {
        List<Type> decoded = decodeNonIndexed(logEntry, event);
        if (decoded.size() < 2) {
            return Optional.empty();
        }

        String account = decodeAddressTopic(logEntry.getTopics(), 1);
        BigInteger delta = asSignedBigInteger(decoded.get(0));
        String verb = delta.signum() >= 0 ? "Adjusted service credits for " : "Reduced service credits for ";
        return Optional.of(buildRecord(
            logEntry,
            "ADJUST_SERVICE_CREDITS",
            verb + account,
            formatCredits(delta.abs()),
            60,
            blockTimestampCache
        ));
    }

    private OnChainEventRecord preferHigherPriorityRecord(OnChainEventRecord left, OnChainEventRecord right) {
        if (right.priority > left.priority) {
            return right;
        }
        if (right.priority < left.priority) {
            return left;
        }
        if (right.logIndex.compareTo(left.logIndex) > 0) {
            return right;
        }
        return left;
    }

    private OnChainEventRecord buildRecord(
        Log logEntry,
        String type,
        String description,
        String amountTokens,
        int priority,
        Map<String, Long> blockTimestampCache
    ) {
        return new OnChainEventRecord(
            logEntry.getTransactionHash(),
            type,
            description,
            amountTokens,
            resolveBlockTimestamp(logEntry, blockTimestampCache),
            safeBigInteger(logEntry.getBlockNumber()),
            safeBigInteger(logEntry.getLogIndex()),
            priority
        );
    }

    private long resolveBlockTimestamp(Log logEntry, Map<String, Long> blockTimestampCache) {
        String blockHash = logEntry.getBlockHash();
        if (blockHash == null || blockHash.isBlank()) {
            return Instant.now().toEpochMilli();
        }
        Long cached = blockTimestampCache.get(blockHash);
        if (cached != null) {
            return cached;
        }
        try {
            EthBlock response = web3j.ethGetBlockByHash(blockHash, false).send();
            if (response != null && response.getBlock() != null && response.getBlock().getTimestamp() != null) {
                long timestamp = response.getBlock().getTimestamp().longValue() * 1000L;
                blockTimestampCache.put(blockHash, timestamp);
                return timestamp;
            }
        } catch (Exception ex) {
            log.debug("Unable to resolve block timestamp for {}: {}", blockHash, LogSanitizer.sanitize(ex.getMessage()));
        }
        return Instant.now().toEpochMilli();
    }

    private String getTransactionSender(String txHash, Map<String, String> txFromCache) {
        if (txHash == null || txHash.isBlank()) {
            return "";
        }
        String cached = txFromCache.get(txHash);
        if (cached != null) {
            return cached;
        }
        try {
            EthTransaction response = web3j.ethGetTransactionByHash(txHash).send();
            Optional<Transaction> maybeTx = response.getTransaction();
            String from = maybeTx.map(Transaction::getFrom).orElse("");
            txFromCache.put(txHash, from);
            return from;
        } catch (Exception ex) {
            log.debug("Unable to resolve tx sender for {}: {}", txHash, LogSanitizer.sanitize(ex.getMessage()));
            return "";
        }
    }

    private String resolveLabDisplayName(BigInteger labId, Map<String, String> labNameCache) {
        if (labId == null) {
            return "selected lab";
        }
        String cacheKey = labId.toString();
        String cached = labNameCache.get(cacheKey);
        if (cached != null && !cached.isBlank()) {
            return cached;
        }

        String fallback = "Lab #" + labId;
        try {
            String resolved = walletService.getLabTokenUri(labId)
                .flatMap(this::resolveLabNameFromMetadata)
                .orElse(fallback);
            labNameCache.put(cacheKey, resolved);
            return resolved;
        } catch (Exception ex) {
            log.debug("Unable to resolve lab name for {}: {}", labId, LogSanitizer.sanitize(ex.getMessage()));
            return fallback;
        }
    }

    private Optional<String> resolveLabNameFromMetadata(String metadataUri) {
        if (metadataUri == null || metadataUri.isBlank()) {
            return Optional.empty();
        }
        try {
            var metadata = labMetadataService.getLabMetadata(metadataUri);
            if (metadata == null || metadata.getName() == null) {
                return Optional.empty();
            }
            String name = metadata.getName().trim();
            return name.isEmpty() ? Optional.empty() : Optional.of(name);
        } catch (RuntimeException ex) {
            log.debug(
                "Unable to resolve lab metadata {}: {}",
                LogSanitizer.sanitize(metadataUri),
                LogSanitizer.sanitize(ex.getMessage())
            );
            return Optional.empty();
        }
    }

    private List<Type> decodeNonIndexed(Log logEntry, Event event) {
        return FunctionReturnDecoder.decode(logEntry.getData(), event.getNonIndexedParameters());
    }

    private BigInteger decodeUint256Topic(List<String> topics, int index) {
        if (topics == null || topics.size() <= index) {
            return BigInteger.ZERO;
        }
        return Numeric.toBigInt(topics.get(index));
    }

    private String decodeAddressTopic(List<String> topics, int index) {
        if (topics == null || topics.size() <= index) {
            return "0x0000000000000000000000000000000000000000";
        }
        String topic = Numeric.cleanHexPrefix(topics.get(index));
        String addressHex = topic.length() > 40 ? topic.substring(topic.length() - 40) : topic;
        return "0x" + addressHex;
    }

    private BigInteger asBigInteger(Type decoded) {
        Object value = decoded != null ? decoded.getValue() : null;
        return value instanceof BigInteger bigInteger ? bigInteger : BigInteger.ZERO;
    }

    private BigInteger asSignedBigInteger(Type decoded) {
        if (decoded instanceof Int intValue && intValue.getValue() instanceof BigInteger bigInteger) {
            return bigInteger;
        }
        Object value = decoded != null ? decoded.getValue() : null;
        return value instanceof BigInteger bigInteger ? bigInteger : BigInteger.ZERO;
    }

    private String formatCredits(BigInteger rawValue) {
        if (rawValue == null) {
            return null;
        }
        BigDecimal decimal = new BigDecimal(rawValue).movePointLeft(LAB_TOKEN_DECIMALS);
        return decimal.stripTrailingZeros().toPlainString() + " credits";
    }

    private String formatPeriodDays(BigInteger seconds) {
        if (seconds == null) {
            return null;
        }
        BigDecimal days = new BigDecimal(seconds).divide(BigDecimal.valueOf(86_400), 2, RoundingMode.HALF_UP);
        return days.stripTrailingZeros().toPlainString() + " days";
    }

    private String receivableStateLabel(BigInteger state) {
        if (state == null) {
            return "UNKNOWN";
        }
        return switch (state.intValue()) {
            case 1 -> "ACCRUED";
            case 2 -> "QUEUED";
            case 3 -> "INVOICED";
            case 4 -> "APPROVED";
            case 5 -> "PAID";
            case 6 -> "REVERSED";
            case 7 -> "DISPUTED";
            default -> "UNKNOWN";
        };
    }

    private String normalizeAddress(String address) {
        return address == null ? "" : address.trim().toLowerCase(Locale.ROOT);
    }

    private String paddedAddressTopic(String address) {
        String clean = Numeric.cleanHexPrefix(address == null ? "" : address).toLowerCase(Locale.ROOT);
        if (clean.length() > 40) {
            clean = clean.substring(clean.length() - 40);
        }
        return "0x" + "0".repeat(64 - clean.length()) + clean;
    }

    private BigInteger safeBigInteger(BigInteger value) {
        return value != null ? value : BigInteger.ZERO;
    }

    @FunctionalInterface
    private interface EventMapper {
        Optional<OnChainEventRecord> map(
            Log logEntry,
            Event event,
            Map<String, Long> blockTimestampCache,
            Map<String, String> txFromCache,
            Map<String, String> labNameCache
        );
    }

    private record OnChainEventRecord(
        String hash,
        String type,
        String description,
        String amountTokens,
        long timestamp,
        BigInteger blockNumber,
        BigInteger logIndex,
        int priority
    ) {}

    private record CacheEntry(long cachedAtEpochMs, List<InstitutionalAnalyticsService.TransactionRecord> records) {}
}
