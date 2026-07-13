package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.AuthResponse;
import java.math.BigInteger;
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
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers(disabledWithoutDocker = true)
class InstitutionalConcurrencyMySqlIntegrationTest {

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
        jdbcTemplate.execute("SET FOREIGN_KEY_CHECKS = 1");
    }

    @Test
    void twoReplicasAllocateDistinctPendingNoncesForDifferentReservations() throws Exception {
        InstitutionalCheckInOutboxService replicaA = outboxService();
        InstitutionalCheckInOutboxService replicaB = outboxService();

        List<BigInteger> nonces = runConcurrently(
            () -> inTransaction(() -> replicaA.reserveNextNonce("0xwallet", BigInteger.valueOf(45))),
            () -> inTransaction(() -> replicaB.reserveNextNonce("0xwallet", BigInteger.valueOf(45)))
        );

        assertThat(nonces).containsExactlyInAnyOrder(BigInteger.valueOf(45), BigInteger.valueOf(46));
        assertThat(jdbcTemplate.queryForObject(
            "SELECT next_nonce FROM institutional_wallet_nonce WHERE wallet_address = ?",
            BigInteger.class,
            "0xwallet"
        )).isEqualTo(BigInteger.valueOf(47));
    }

    @Test
    void concurrentRequestsForOneReservationCreateOneOutboxTransactionAndNeverReopenIt() throws Exception {
        InstitutionalCheckInOutboxService replicaA = outboxService();
        InstitutionalCheckInOutboxService replicaB = outboxService();

        List<InstitutionalCheckInOutboxRecord> records = runConcurrently(
            () -> replicaA.enqueueAccessGranted("0xreservation", "42", "0xwallet", "0xpuc", "session-a"),
            () -> replicaB.enqueueAccessGranted("0xreservation", "42", "0xwallet", "0xpuc", "session-b")
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
            "0xreservation", "42", "0xwallet", "0xpuc", "session-c"
        );

        assertThat(existing.status()).isEqualTo("SUBMITTED");
        assertThat(existing.nonce()).isEqualTo(BigInteger.valueOf(45));
        assertThat(existing.txHash()).isEqualTo("0xtx");
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
