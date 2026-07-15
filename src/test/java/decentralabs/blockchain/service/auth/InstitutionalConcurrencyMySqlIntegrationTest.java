package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.AuthResponse;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers(disabledWithoutDocker = true)
class InstitutionalConcurrencyMySqlIntegrationTest {

    private static final BigInteger CHAIN_ID = BigInteger.valueOf(11155111);

    @Container
    @SuppressWarnings("resource")
    private static final MySQLContainer MYSQL = new MySQLContainer("mysql:8.4")
        .withDatabaseName("blockchain_services")
        .withUsername("test")
        .withPassword("test");

    private static DriverManagerDataSource dataSource;
    private JdbcTemplate jdbcTemplate;
    private TransactionTemplate transactions;

    @BeforeAll
    static void migrateSchema() {
        dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
        dataSource.setUrl(MYSQL.getJdbcUrl());
        dataSource.setUsername(MYSQL.getUsername());
        dataSource.setPassword(MYSQL.getPassword());
        Flyway.configure()
            .dataSource(dataSource)
            .locations("classpath:db/migration")
            .load()
            .migrate();
    }

    @BeforeEach
    void resetState() {
        jdbcTemplate = new JdbcTemplate(dataSource);
        transactions = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        jdbcTemplate.execute("SET FOREIGN_KEY_CHECKS = 0");
        jdbcTemplate.update("DELETE FROM lab_access_codes");
        jdbcTemplate.update("DELETE FROM access_authorization_provisioning");
        jdbcTemplate.update("DELETE FROM institutional_checkin_outbox");
        jdbcTemplate.update("DELETE FROM institutional_wallet_nonce");
        jdbcTemplate.update("DELETE FROM session_started_attestations");
        jdbcTemplate.execute("SET FOREIGN_KEY_CHECKS = 1");
    }

    @Test
    void twoReplicasAllocateDistinctPendingNoncesForDifferentReservations() throws Exception {
        InstitutionalCheckInOutboxService replicaA = outboxService();
        InstitutionalCheckInOutboxService replicaB = outboxService();

        List<BigInteger> nonces = runConcurrently(
            () -> inTransaction(() -> replicaA.reserveNextNonce(CHAIN_ID, "0xwallet", BigInteger.valueOf(45))),
            () -> inTransaction(() -> replicaB.reserveNextNonce(CHAIN_ID, "0xwallet", BigInteger.valueOf(45)))
        );

        assertThat(nonces).containsExactlyInAnyOrder(BigInteger.valueOf(45), BigInteger.valueOf(46));
        assertThat(jdbcTemplate.queryForObject(
            "SELECT next_nonce FROM institutional_wallet_nonce WHERE chain_id = ? AND wallet_address = ?",
            BigInteger.class,
            CHAIN_ID,
            "0xwallet"
        )).isEqualTo(BigInteger.valueOf(47));
    }

    @Test
    void concurrentRequestsForOneReservationCreateOneOutboxTransactionAndNeverReopenIt() throws Exception {
        InstitutionalCheckInOutboxService replicaA = outboxService();
        InstitutionalCheckInOutboxService replicaB = outboxService();

        List<InstitutionalCheckInOutboxRecord> records = runConcurrently(
            () -> replicaA.enqueueAccessGranted(
                "0xreservation", "42", "0xwallet", "0xwallet", "0xpuc", "session-a"
            ),
            () -> replicaB.enqueueAccessGranted(
                "0xreservation", "42", "0xwallet", "0xwallet", "0xpuc", "session-b"
            )
        );

        assertThat(records.get(0).id()).isEqualTo(records.get(1).id());
        assertThat(jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM institutional_checkin_outbox WHERE reservation_key = '0xreservation'",
            Integer.class
        )).isEqualTo(1);

        jdbcTemplate.update(
            "UPDATE institutional_checkin_outbox SET status = 'SUBMITTED', wallet_address = ?, nonce = ?, "
                + "tx_hash = ?, submitted_at = CURRENT_TIMESTAMP WHERE reservation_key = ?",
            "0xwallet", BigInteger.valueOf(45), "0xtx", "0xreservation"
        );
        InstitutionalCheckInOutboxRecord existing = replicaB.enqueueAccessGranted(
            "0xreservation", "42", "0xwallet", "0xwallet", "0xpuc", "session-c"
        );

        assertThat(existing.status()).isEqualTo("SUBMITTED");
        assertThat(existing.nonce()).isEqualTo(BigInteger.valueOf(45));
        assertThat(existing.txHash()).isEqualTo("0xtx");
    }

    @Test
    void claimLeaseUsesTheDatabaseClock() {
        InstitutionalCheckInOutboxService service = outboxService();
        InstitutionalCheckInOutboxRecord record = service.enqueueAccessGranted(
            "0xlease-reservation", "42", "0xwallet", "0xwallet", "0xpuc", "session"
        );

        assertThat(service.claim(record.id())).isNotNull();

        java.sql.Timestamp databaseNow = jdbcTemplate.queryForObject(
            "SELECT CURRENT_TIMESTAMP(6)", java.sql.Timestamp.class
        );
        java.sql.Timestamp expiresAt = jdbcTemplate.queryForObject(
            "SELECT claim_expires_at FROM institutional_checkin_outbox WHERE id = ?",
            java.sql.Timestamp.class,
            record.id()
        );
        long leaseMillis = java.time.Duration.between(
            databaseNow.toInstant(), expiresAt.toInstant()
        ).toMillis();

        assertThat(leaseMillis).isBetween(899_000L, 901_000L);
    }

    @Test
    void legacyPayerSignerContextIsRepairedOnlyBeforeOnchainMaterialExists() {
        InstitutionalCheckInOutboxService service = outboxService();
        InstitutionalCheckInOutboxRecord legacy = service.enqueueAccessGranted(
            "0xlegacy-signer", "42", "0xpayer", "0xpayer", "0xpuc", "session"
        );

        InstitutionalCheckInOutboxRecord repaired = service.enqueueAccessGranted(
            "0xlegacy-signer", "42", "0xpayer", "0xbackend-signer", "0xpuc", "session"
        );
        assertThat(repaired.walletAddress()).isEqualTo("0xbackend-signer");

        jdbcTemplate.update(
            "UPDATE institutional_checkin_outbox SET chain_id = ?, nonce = ?, tx_hash = ?, "
                + "signed_raw_transaction = ? WHERE id = ?",
            CHAIN_ID, BigInteger.valueOf(45), "0x" + "a".repeat(64), "0xraw", legacy.id()
        );
        InstitutionalCheckInOutboxRecord preserved = service.enqueueAccessGranted(
            "0xlegacy-signer", "42", "0xpayer", "0xother-signer", "0xpuc", "session"
        );

        assertThat(preserved.walletAddress()).isEqualTo("0xbackend-signer");
    }

    @Test
    void onlyOneReplicaOwnsAReservationLeaseAndAStaleOwnerCannotRollbackTheReplacement() throws Exception {
        AccessAuthorizationProvisioningService replicaA = provisioningService();
        AccessAuthorizationProvisioningService replicaB = provisioningService();

        List<AccessAuthorizationProvisioningService.ProvisioningLease> attempts = runConcurrently(
            () -> replicaA.tryStart("0xreservation"),
            () -> replicaB.tryStart("0xreservation")
        );
        AccessAuthorizationProvisioningService.ProvisioningLease firstLease = attempts.stream()
            .filter(java.util.Objects::nonNull)
            .findFirst()
            .orElseThrow();

        assertThat(attempts).hasSize(2);
        assertThat(attempts.stream().filter(java.util.Objects::nonNull)).hasSize(1);

        jdbcTemplate.update(
            "UPDATE access_authorization_provisioning SET expires_at = ? WHERE reservation_key = ?",
            java.sql.Timestamp.from(Instant.now().minusSeconds(1)),
            "0xreservation"
        );
        AccessAuthorizationProvisioningService.ProvisioningLease replacement = replicaB.tryStart("0xreservation");

        assertThat(replacement).isNotNull();
        assertThat(replacement.generation()).isEqualTo(firstLease.generation() + 1);
        assertThat(replicaA.beginRollback(firstLease)).isFalse();
        assertThat(replicaB.beginRollback(replacement)).isTrue();
    }

    @Test
    void anAccessCodeCanBeRedeemedOnlyOnceAcrossTwoReplicas() throws Exception {
        JwtService jwtService = mock(JwtService.class);
        when(jwtService.extractAllClaims("signed-jwt")).thenReturn(Map.of(
            "resourceType", "lab",
            "labURL", "https://lab.example/guacamole/",
            "aud", "https://lab.example/guacamole/",
            "targetGatewayId", "lab.example",
            "exp", Instant.now().plusSeconds(600).getEpochSecond()
        ));
        AccessCodeTokenCipher cipher = new AccessCodeTokenCipher(
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"
        );
        AccessCodeService replicaA = new AccessCodeService(provider(new JdbcTemplate(dataSource)), jwtService, cipher);
        AccessCodeService replicaB = new AccessCodeService(provider(new JdbcTemplate(dataSource)), jwtService, cipher);
        String code = replicaA.issue("signed-jwt").getAccessCode();

        List<Boolean> redeemed = runConcurrently(
            () -> redeem(replicaA, code),
            () -> redeem(replicaB, code)
        );

        assertThat(redeemed).containsExactlyInAnyOrder(true, false);
        assertThat(jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM lab_access_codes WHERE code_hash IS NOT NULL AND consumed_at IS NULL",
            Integer.class
        )).isZero();
    }

    @Test
    void onlyOneSessionStartedAttestationCanOwnPublicationForAReservation() throws Exception {
        long first = insertAttestation("session-a", "0x" + "1".repeat(64));
        long second = insertAttestation("session-b", "0x" + "2".repeat(64));

        List<Boolean> claimed = runConcurrently(
            () -> claimSessionStarted(first),
            () -> claimSessionStarted(second)
        );

        assertThat(claimed).containsExactlyInAnyOrder(true, false);
        assertThat(jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM session_started_attestations WHERE onchain_reservation_guard = '0xreservation'",
            Integer.class
        )).isEqualTo(1);
    }

    @Test
    void sessionStartedPublisherFencesDurableWritesWithDatabaseOwnedClaim() throws Exception {
        String signer = "0x1111111111111111111111111111111111111111";
        long attestationId = insertAttestation(
            "session-publisher", "0x" + "1".repeat(64), signer
        );
        SessionStartedOnChainClient client = mock(SessionStartedOnChainClient.class);
        InstitutionalWalletTransactionDispatcher dispatcher = mock(
            InstitutionalWalletTransactionDispatcher.class
        );
        InstitutionalWalletTransactionDispatcher.PreparedTransaction prepared =
            new InstitutionalWalletTransactionDispatcher.PreparedTransaction(
                "0x01", "0x" + "a".repeat(64), BigInteger.ONE
            );

        when(client.connectedChainId()).thenReturn(CHAIN_ID);
        when(client.signerAddress()).thenReturn(signer);
        when(client.hasSessionStarted("0xreservation")).thenReturn(false);
        when(client.prepareSessionStarted(any(), eq(BigInteger.valueOf(45)), eq(0)))
            .thenReturn(prepared);
        doAnswer(invocation -> {
            BiConsumer<BigInteger, BigInteger> persistNonce = invocation.getArgument(3);
            persistNonce.accept(CHAIN_ID, BigInteger.valueOf(45));

            Timestamp databaseNow = jdbcTemplate.queryForObject(
                "SELECT CURRENT_TIMESTAMP(6)", Timestamp.class
            );
            Timestamp claimExpiresAt = jdbcTemplate.queryForObject(
                "SELECT onchain_claim_expires_at FROM session_started_attestations WHERE id = ?",
                Timestamp.class,
                attestationId
            );
            assertThat(Duration.between(databaseNow.toInstant(), claimExpiresAt.toInstant()).toMillis())
                .isBetween(299_000L, 301_000L);
            assertThat(jdbcTemplate.queryForObject(
                "SELECT onchain_claim_id FROM session_started_attestations WHERE id = ?",
                String.class,
                attestationId
            )).isNotBlank();

            Function<BigInteger, InstitutionalWalletTransactionDispatcher.PreparedTransaction> prepare =
                invocation.getArgument(4);
            Consumer<InstitutionalWalletTransactionDispatcher.PreparedTransaction> persistPrepared =
                invocation.getArgument(5);
            Consumer<String> persistHash = invocation.getArgument(6);
            InstitutionalWalletTransactionDispatcher.PreparedTransaction transaction =
                prepare.apply(BigInteger.valueOf(45));
            persistPrepared.accept(transaction);
            persistHash.accept(transaction.transactionHash());
            return transaction.transactionHash();
        }).when(dispatcher).dispatchPrepared(
            eq(signer), any(), any(), any(), any(), any(), any()
        );

        SessionStartedOnChainPublisherService publisher = new SessionStartedOnChainPublisherService(
            provider(new JdbcTemplate(dataSource)), client, dispatcher
        );
        ReflectionTestUtils.setField(publisher, "claimLeaseMillis", 300_000L);

        assertThat(publisher.publishPending(10)).isEqualTo(1);
        Map<String, Object> row = jdbcTemplate.queryForMap(
            "SELECT onchain_status, onchain_wallet_address, onchain_chain_id, onchain_nonce, "
                + "onchain_tx_hash, onchain_claim_id FROM session_started_attestations WHERE id = ?",
            attestationId
        );
        assertThat(row.get("onchain_status")).isEqualTo("SUBMITTED");
        assertThat(row.get("onchain_wallet_address")).isEqualTo(signer);
        assertThat(((Number) row.get("onchain_chain_id")).longValue()).isEqualTo(CHAIN_ID.longValue());
        assertThat(((Number) row.get("onchain_nonce")).longValue()).isEqualTo(45L);
        assertThat(row.get("onchain_tx_hash")).isEqualTo(prepared.transactionHash());
        assertThat(row.get("onchain_claim_id")).isNull();
    }

    @Test
    void exhaustedStaleSessionStartedClaimBecomesManualInterventionWithoutReleasingGuard() {
        String signer = "0x1111111111111111111111111111111111111111";
        long attestationId = insertAttestation(
            "session-exhausted", "0x" + "3".repeat(64), signer
        );
        jdbcTemplate.update(
            "UPDATE session_started_attestations SET onchain_status = 'SUBMITTING', "
                + "onchain_publish_attempts = ?, onchain_reservation_guard = reservation_key, "
                + "onchain_publish_locked_at = DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 10 MINUTE), "
                + "onchain_claim_id = ?, onchain_claimed_by = ?, onchain_claim_version = ?, "
                + "onchain_claim_expires_at = DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 MINUTE) "
                + "WHERE id = ?",
            3, "expired-claim", "worker-a", 1L, attestationId
        );
        SessionStartedOnChainClient client = mock(SessionStartedOnChainClient.class);
        InstitutionalWalletTransactionDispatcher dispatcher = mock(
            InstitutionalWalletTransactionDispatcher.class
        );
        when(client.connectedChainId()).thenReturn(CHAIN_ID);
        when(client.signerAddress()).thenReturn(signer);
        SessionStartedOnChainPublisherService publisher = new SessionStartedOnChainPublisherService(
            provider(new JdbcTemplate(dataSource)), client, dispatcher
        );
        ReflectionTestUtils.setField(publisher, "maxAttempts", 3);

        assertThat(publisher.publishPending(10)).isEqualTo(1);
        Map<String, Object> row = jdbcTemplate.queryForMap(
            "SELECT onchain_status, onchain_reservation_guard, onchain_claim_id "
                + "FROM session_started_attestations WHERE id = ?",
            attestationId
        );
        assertThat(row.get("onchain_status")).isEqualTo("MANUAL_INTERVENTION");
        assertThat(row.get("onchain_reservation_guard")).isEqualTo("0xreservation");
        assertThat(row.get("onchain_claim_id")).isNull();
    }

    private long insertAttestation(String sessionId, String nonce) {
        return insertAttestation(
            sessionId, nonce, "0x1111111111111111111111111111111111111111"
        );
    }

    private long insertAttestation(String sessionId, String nonce, String signer) {
        jdbcTemplate.update(
            """
            INSERT INTO session_started_attestations (
                reservation_key, signer_address, session_id, access_type, started_at,
                nonce, digest, signature, credential_reference_type, credential_reference_id
            ) VALUES (?, ?, ?, 'fmu', CURRENT_TIMESTAMP, ?, ?, ?, 'jwt_jti', ?)
            """,
            "0xreservation", signer, sessionId,
            nonce, nonce, "0x" + "a".repeat(130), sessionId
        );
        return jdbcTemplate.queryForObject(
            "SELECT id FROM session_started_attestations WHERE session_id = ?",
            Long.class,
            sessionId
        );
    }

    private boolean claimSessionStarted(long id) {
        try {
            return jdbcTemplate.update(
                "UPDATE session_started_attestations SET onchain_reservation_guard = reservation_key, "
                    + "onchain_status = 'SUBMITTING' WHERE id = ?",
                id
            ) == 1;
        } catch (DuplicateKeyException ex) {
            return false;
        }
    }

    private boolean redeem(AccessCodeService service, String code) {
        try {
            AuthResponse response = inTransaction(() -> service.redeem(code, "lab.example"));
            return response != null && "signed-jwt".equals(response.getToken());
        } catch (ResponseStatusException ex) {
            return false;
        }
    }

    private InstitutionalCheckInOutboxService outboxService() {
        return new InstitutionalCheckInOutboxService(provider(new JdbcTemplate(dataSource)));
    }

    private AccessAuthorizationProvisioningService provisioningService() {
        return new AccessAuthorizationProvisioningService(provider(new JdbcTemplate(dataSource)));
    }

    private <T> ObjectProvider<T> provider(T bean) {
        StaticListableBeanFactory factory = new StaticListableBeanFactory();
        factory.addBean("testBean", bean);
        @SuppressWarnings("unchecked")
        Class<T> type = (Class<T>) bean.getClass();
        return factory.getBeanProvider(type);
    }

    private <T> T inTransaction(Supplier<T> action) {
        return transactions.execute(status -> action.get());
    }

    @SafeVarargs
    private final <T> List<T> runConcurrently(Callable<T>... actions) throws Exception {
        CountDownLatch ready = new CountDownLatch(actions.length);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(actions.length);
        try {
            List<Future<T>> futures = new ArrayList<>();
            for (Callable<T> action : actions) {
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    if (!start.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Concurrent test start timed out");
                    }
                    return action.call();
                }));
            }
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            List<T> results = new ArrayList<>();
            for (Future<T> future : futures) {
                results.add(future.get(30, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            executor.shutdownNow();
        }
    }
}
