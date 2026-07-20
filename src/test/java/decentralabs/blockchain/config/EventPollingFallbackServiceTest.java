package decentralabs.blockchain.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.reactivex.Flowable;
import io.reactivex.disposables.Disposable;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Event;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthBlockNumber;
import org.web3j.protocol.core.methods.response.EthLog;
import org.web3j.protocol.core.methods.response.Log;

class EventPollingFallbackServiceTest {

    private EventPollingFallbackService service;

    @BeforeEach
    void setUp() {
        service = new EventPollingFallbackService(null);
        ReflectionTestUtils.setField(service, "pollingEnabled", false);
        ReflectionTestUtils.setField(service, "websocketEnabled", false);
        ReflectionTestUtils.setField(service, "pollingIntervalSeconds", 1);
        ReflectionTestUtils.setField(service, "maxBlockRange", 1000);
        ReflectionTestUtils.setField(service, "lookbackBlocks", 5);
        ReflectionTestUtils.setField(service, "durableJournalRequired", false);
    }

    @Test
    void registerEvent_tracksRegistrationCountAndStartBlock() {
        Event event = new Event("ReservationRequested", List.of(TypeReference.create(Uint256.class)));

        service.registerEvent("ReservationRequested", event, BigInteger.valueOf(12), log -> {});

        assertThat(service.getRegisteredEventCount()).isEqualTo(1);
        assertThat(service.getLastProcessedBlock(org.web3j.abi.EventEncoder.encode(event))).isEqualTo(BigInteger.valueOf(12));
    }

    @Test
    void handleEventLog_deduplicatesWithoutAdvancingPollingCursor() {
        Event event = new Event("ReservationRequested", List.of(TypeReference.create(Uint256.class)));
        AtomicInteger handled = new AtomicInteger();
        service.registerEvent("ReservationRequested", event, null, log -> handled.incrementAndGet());

        String signature = org.web3j.abi.EventEncoder.encode(event);
        Object registration = ((Map<?, ?>) ReflectionTestUtils.getField(service, "registeredEvents")).get(signature);
        Log log = log(signature, "0xtx1", BigInteger.ONE, BigInteger.valueOf(25));

        boolean first = (boolean) ReflectionTestUtils.invokeMethod(service, "handleEventLog", registration, log, "polling");
        boolean second = (boolean) ReflectionTestUtils.invokeMethod(service, "handleEventLog", registration, log, "websocket");

        assertThat(first).isTrue();
        assertThat(second).isFalse();
        assertThat(handled.get()).isEqualTo(1);
        assertThat(service.getLastProcessedBlock(signature)).isNull();
    }

    @Test
    void cleanupDeduplicationCache_removesExpiredEntries() {
        @SuppressWarnings("unchecked")
        Map<String, Instant> cache = (Map<String, Instant>) ReflectionTestUtils.getField(service, "recentlyProcessed");
        assertThat(cache).isNotNull();
        cache.put("expired", Instant.now().minusSeconds(601));
        cache.put("fresh", Instant.now());

        ReflectionTestUtils.invokeMethod(service, "cleanupDeduplicationCache");

        assertThat(cache).containsKey("fresh");
        assertThat(cache).doesNotContainKey("expired");
    }

    @Test
    void pollForMissedEvents_processesLogsAndUpdatesLastProcessedBlock() throws Exception {
        Web3j web3j = mock(Web3j.class);
        Event event = new Event("ReservationRequested", List.of(TypeReference.create(Uint256.class)));
        AtomicInteger handled = new AtomicInteger();
        service.initialize(web3j, "0xcontract");
        service.registerEvent("ReservationRequested", event, null, log -> handled.incrementAndGet());
        ReflectionTestUtils.setField(service, "started", true);

        stubBlockNumber(web3j, 15L);
        EthLog.LogObject logObject = new EthLog.LogObject();
        logObject.setTopics(List.of(org.web3j.abi.EventEncoder.encode(event)));
        logObject.setTransactionHash("0xtx1");
        logObject.setLogIndex("0x1");
        logObject.setBlockNumber("0xf");
        stubLogs(web3j, logObject);

        ReflectionTestUtils.invokeMethod(service, "pollForMissedEvents");

        assertThat(handled.get()).isEqualTo(1);
        assertThat(service.getLastProcessedBlock(org.web3j.abi.EventEncoder.encode(event))).isEqualTo(BigInteger.valueOf(15));
    }

    @Test
    void isSubscriptionActive_checksDisposableState() {
        Disposable disposable = mock(Disposable.class);
        when(disposable.isDisposed()).thenReturn(false);
        @SuppressWarnings("unchecked")
        Map<String, Disposable> subscriptions = (Map<String, Disposable>) ReflectionTestUtils.getField(service, "activeSubscriptions");
        assertThat(subscriptions).isNotNull();
        subscriptions.put("sig", disposable);

        assertThat(service.isSubscriptionActive("sig")).isTrue();
        assertThat(service.isSubscriptionActive("missing")).isFalse();
    }

    @Test
    void start_andStop_manageLifecycleAndSubscriptions() {
        Web3j web3j = mock(Web3j.class);
        Event event = new Event("ReservationRequested", List.of(TypeReference.create(Uint256.class)));
        ReflectionTestUtils.setField(service, "websocketEnabled", true);
        service.initialize(web3j, "0xcontract");
        service.registerEvent("ReservationRequested", event, null, log -> {});
        when(web3j.ethLogFlowable(any())).thenReturn(Flowable.never());

        service.start();

        String signature = org.web3j.abi.EventEncoder.encode(event);
        assertThat(service.isSubscriptionActive(signature)).isTrue();
        assertThat(ReflectionTestUtils.getField(service, "started")).isEqualTo(true);

        service.stop();

        assertThat(service.isSubscriptionActive(signature)).isFalse();
        assertThat(ReflectionTestUtils.getField(service, "started")).isEqualTo(false);
    }

    @Test
    void start_withoutInitialization_keepsServiceStopped() {
        service.start();

        assertThat(ReflectionTestUtils.getField(service, "started")).isEqualTo(false);
    }

    @Test
    void start_refusesMemoryOnlyEventListeningWhenDurableJournalIsRequired() {
        Web3j web3j = mock(Web3j.class);
        ReflectionTestUtils.setField(service, "durableJournalRequired", true);
        service.initialize(web3j, "0xcontract");

        service.start();

        assertThat(ReflectionTestUtils.getField(service, "started")).isEqualTo(false);
    }

    @Test
    void handleEventLog_usesDurableJournalAndAcknowledgesAfterHandler() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        ReflectionTestUtils.setField(service, "jdbcTemplate", jdbcTemplate);
        ReflectionTestUtils.setField(service, "durableJournalRequired", true);
        when(jdbcTemplate.query(
            anyString(),
            any(PreparedStatementSetter.class),
            org.mockito.ArgumentMatchers.<RowMapper<Object>>any()
        )).thenReturn(List.of());
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        when(jdbcTemplate.queryForObject(anyString(), eq(Integer.class), any(Object[].class))).thenReturn(1);

        Web3j web3j = mock(Web3j.class);
        AtomicInteger handled = new AtomicInteger();
        Event event = new Event("ReservationRequested", List.of(TypeReference.create(Uint256.class)));
        service.initialize(web3j, "0xcontract");
        service.registerEvent("ReservationRequested", event, null, log -> handled.incrementAndGet());
        String signature = org.web3j.abi.EventEncoder.encode(event);
        Object registration = ((Map<?, ?>) ReflectionTestUtils.getField(service, "registeredEvents")).get(signature);

        assertThat((boolean) ReflectionTestUtils.invokeMethod(
            service,
            "handleEventLog",
            registration,
            log(signature, "0xdurable", BigInteger.ONE, BigInteger.valueOf(20)),
            "polling"
        )).isTrue();
        assertThat(handled.get()).isEqualTo(1);
        verify(jdbcTemplate).update(contains("INSERT IGNORE INTO contract_event_journal"), any(Object[].class));
        verify(jdbcTemplate).update(contains("SET status='PROCESSING'"), any(Object[].class));
        verify(jdbcTemplate).update(contains("SET status='DONE'"), any(Object[].class));
    }

    @Test
    void resetForNetworkSwitch_clearsCachesAndRestarts() {
        Web3j first = mock(Web3j.class);
        Web3j second = mock(Web3j.class);
        Event event = new Event("ReservationRequested", List.of(TypeReference.create(Uint256.class)));
        service.initialize(first, "0xcontract-a");
        service.registerEvent("ReservationRequested", event, BigInteger.valueOf(9), log -> {});
        ReflectionTestUtils.setField(service, "started", true);
        @SuppressWarnings("unchecked")
        Map<String, Instant> dedup = (Map<String, Instant>) ReflectionTestUtils.getField(service, "recentlyProcessed");
        dedup.put("tx-1", Instant.now());

        service.resetForNetworkSwitch(second, "0xcontract-b");

        assertThat(ReflectionTestUtils.getField(service, "web3j")).isSameAs(second);
        assertThat(ReflectionTestUtils.getField(service, "contractAddress")).isEqualTo("0xcontract-b");
        assertThat(service.getLastProcessedBlock(org.web3j.abi.EventEncoder.encode(event))).isNull();
        assertThat(dedup).isEmpty();
        assertThat(ReflectionTestUtils.getField(service, "started")).isEqualTo(true);
    }

    @Test
    void handleEventLog_returnsFalseForMissingTopicsMismatchesAndHandlerErrors() {
        Event event = new Event("ReservationRequested", List.of(TypeReference.create(Uint256.class)));
        service.registerEvent("ReservationRequested", event, null, log -> {
            throw new IllegalStateException("boom");
        });

        String signature = org.web3j.abi.EventEncoder.encode(event);
        Object registration = ((Map<?, ?>) ReflectionTestUtils.getField(service, "registeredEvents")).get(signature);

        assertThat((boolean) ReflectionTestUtils.invokeMethod(service, "handleEventLog", registration, new Log(), "polling"))
            .isFalse();
        assertThat((boolean) ReflectionTestUtils.invokeMethod(
            service,
            "handleEventLog",
            registration,
            log("0xdeadbeef", "0xtx2", BigInteger.TWO, BigInteger.TEN),
            "polling"
        )).isFalse();
        assertThat((boolean) ReflectionTestUtils.invokeMethod(
            service,
            "handleEventLog",
            registration,
            log(signature, "0xtx3", BigInteger.valueOf(3), BigInteger.valueOf(20)),
            "polling"
        )).isFalse();
    }

    @Test
    void handleEventLog_retriesAfterHandlerFailureInsteadOfPoisoningDeduplication() {
        Event event = new Event("ReservationRequested", List.of(TypeReference.create(Uint256.class)));
        AtomicInteger attempts = new AtomicInteger();
        service.registerEvent("ReservationRequested", event, null, log -> {
            if (attempts.incrementAndGet() == 1) {
                throw new IllegalStateException("transient failure");
            }
        });

        String signature = org.web3j.abi.EventEncoder.encode(event);
        Object registration = ((Map<?, ?>) ReflectionTestUtils.getField(service, "registeredEvents")).get(signature);
        Log eventLog = log(signature, "0xretryable", BigInteger.ONE, BigInteger.valueOf(20));

        assertThat((boolean) ReflectionTestUtils.invokeMethod(service, "handleEventLog", registration, eventLog, "polling"))
            .isFalse();
        assertThat((boolean) ReflectionTestUtils.invokeMethod(service, "handleEventLog", registration, eventLog, "polling"))
            .isTrue();
        assertThat(attempts.get()).isEqualTo(2);
    }

    @Test
    void pollEventsForRegistration_doesNotAdvanceCursorWhenHandlerFails() throws Exception {
        Web3j web3j = mock(Web3j.class);
        Event event = new Event("ReservationRequested", List.of(TypeReference.create(Uint256.class)));
        service.initialize(web3j, "0xcontract");
        service.registerEvent("ReservationRequested", event, BigInteger.valueOf(15), log -> {
            throw new IllegalStateException("transient failure");
        });
        String signature = org.web3j.abi.EventEncoder.encode(event);
        Object registration = ((Map<?, ?>) ReflectionTestUtils.getField(service, "registeredEvents")).get(signature);

        EthLog.LogObject logObject = new EthLog.LogObject();
        logObject.setTopics(List.of(signature));
        logObject.setTransactionHash("0xfailed-handler");
        logObject.setLogIndex("0x1");
        logObject.setBlockNumber("0x10");
        stubLogs(web3j, logObject);

        ReflectionTestUtils.invokeMethod(service, "pollEventsForRegistration", registration, BigInteger.valueOf(16));

        assertThat(service.getLastProcessedBlock(signature)).isEqualTo(BigInteger.valueOf(15));
    }

    @Test
    void pollEventsForRegistration_handlesEthLogErrorsAndUpToDateRanges() throws Exception {
        Web3j web3j = mock(Web3j.class);
        Event event = new Event("ReservationRequested", List.of(TypeReference.create(Uint256.class)));
        service.initialize(web3j, "0xcontract");
        service.registerEvent("ReservationRequested", event, BigInteger.valueOf(15), log -> {});
        String signature = org.web3j.abi.EventEncoder.encode(event);
        Object registration = ((Map<?, ?>) ReflectionTestUtils.getField(service, "registeredEvents")).get(signature);

        EthLog errorResponse = new EthLog();
        errorResponse.setError(new org.web3j.protocol.core.Response.Error(1, "rpc down"));
        stubLogs(web3j, errorResponse);
        ReflectionTestUtils.invokeMethod(service, "pollEventsForRegistration", registration, BigInteger.valueOf(20));

        assertThat(service.getLastProcessedBlock(signature)).isEqualTo(BigInteger.valueOf(15));

        ReflectionTestUtils.invokeMethod(service, "pollEventsForRegistration", registration, BigInteger.valueOf(14));

        assertThat(service.getLastProcessedBlock(signature)).isEqualTo(BigInteger.valueOf(15));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubBlockNumber(Web3j web3j, long value) throws Exception {
        Request request = mock(Request.class);
        EthBlockNumber response = new EthBlockNumber();
        response.setResult("0x" + Long.toHexString(value));
        when(web3j.ethBlockNumber()).thenReturn(request);
        when(request.send()).thenReturn(response);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubLogs(Web3j web3j, EthLog.LogObject logObject) throws Exception {
        Request request = mock(Request.class);
        EthLog response = new EthLog();
        response.setResult(List.of(logObject));
        when(web3j.ethGetLogs(org.mockito.ArgumentMatchers.any())).thenReturn(request);
        when(request.send()).thenReturn(response);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubLogs(Web3j web3j, EthLog response) throws Exception {
        Request request = mock(Request.class);
        when(web3j.ethGetLogs(org.mockito.ArgumentMatchers.any())).thenReturn(request);
        when(request.send()).thenReturn(response);
    }

    private Log log(String signature, String txHash, BigInteger logIndex, BigInteger blockNumber) {
        Log log = new Log();
        log.setTopics(List.of(signature));
        log.setTransactionHash(txHash);
        log.setLogIndex("0x" + logIndex.toString(16));
        log.setBlockNumber("0x" + blockNumber.toString(16));
        return log;
    }
}
