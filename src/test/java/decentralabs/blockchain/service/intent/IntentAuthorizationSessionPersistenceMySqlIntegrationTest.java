package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mysql.MySQLContainer;

@Testcontainers(disabledWithoutDocker = true)
class IntentAuthorizationSessionPersistenceMySqlIntegrationTest {

    @Container
    @SuppressWarnings("resource")
    private static final MySQLContainer MYSQL = new MySQLContainer("mysql:8.4")
        .withDatabaseName("blockchain_services")
        .withUsername("test")
        .withPassword("test");

    private static JdbcTemplate jdbcTemplate;
    private IntentPayloadCipher payloadCipher;

    @BeforeAll
    static void migrateSchema() {
        DataSource dataSource = new DriverManagerDataSource(
            MYSQL.getJdbcUrl(), MYSQL.getUsername(), MYSQL.getPassword()
        );
        Flyway.configure()
            .dataSource(dataSource)
            .locations("classpath:db/migration")
            .load()
            .migrate();
        jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @BeforeEach
    void resetState() {
        jdbcTemplate.update("DELETE FROM intent_authorization_sessions");
        payloadCipher = new IntentPayloadCipher("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY");
    }

    @AfterEach
    void cleanState() {
        jdbcTemplate.update("DELETE FROM intent_authorization_sessions");
    }

    @Test
    void twoReplicasCanClaimOnlyOneCompletionAndPersistTheResult() throws Exception {
        IntentAuthorizationSessionPersistenceService replicaA = persistenceReplica();
        IntentAuthorizationSessionPersistenceService replicaB = persistenceReplica();
        replicaA.create(session());

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Optional<IntentAuthorizationSessionPersistenceService.ClaimedSession>> first =
                executor.submit(() -> replicaA.claim("0123456789abcdef0123456789abcdef", 60));
            Future<Optional<IntentAuthorizationSessionPersistenceService.ClaimedSession>> second =
                executor.submit(() -> replicaB.claim("0123456789abcdef0123456789abcdef", 60));

            Optional<IntentAuthorizationSessionPersistenceService.ClaimedSession> firstClaim = first.get();
            Optional<IntentAuthorizationSessionPersistenceService.ClaimedSession> secondClaim = second.get();

            long successfulClaims = (firstClaim.isPresent() ? 1L : 0L)
                + (secondClaim.isPresent() ? 1L : 0L);
            assertThat(successfulClaims).isEqualTo(1L);
            IntentAuthorizationSessionPersistenceService.ClaimedSession claim = firstClaim.orElseGet(secondClaim::orElseThrow);
            IntentAckResponse ack = new IntentAckResponse();
            ack.setRequestId("request-123");
            ack.setStatus("accepted");

            assertThat(replicaA.complete(claim, "SUCCESS", ack, null, 200, Instant.now(), 300)
                || replicaB.complete(claim, "SUCCESS", ack, null, 200, Instant.now(), 300)).isTrue();
            IntentAuthorizationSessionPersistenceService.StoredSession stored =
                replicaB.find("0123456789abcdef0123456789abcdef").orElseThrow();
            assertThat(stored.status()).isEqualTo("SUCCESS");
        } finally {
            executor.shutdownNow();
            executor.awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    private IntentAuthorizationSessionPersistenceService persistenceReplica() {
        JdbcTemplate replicaJdbcTemplate = new JdbcTemplate(jdbcTemplate.getDataSource());
        @SuppressWarnings("unchecked")
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(replicaJdbcTemplate);
        return new IntentAuthorizationSessionPersistenceService(provider, new ObjectMapper(), payloadCipher);
    }

    private IntentAuthorizationService.AuthorizationSession session() {
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("request-123");
        meta.setSigner("0xsigner");
        meta.setExecutor("0xexecutor");
        meta.setAction(3);
        meta.setPayloadHash("0xpayload");
        meta.setNonce(7L);
        meta.setRequestedAt(100L);
        meta.setExpiresAt(200L);

        ActionIntentPayload payload = new ActionIntentPayload();
        payload.setExecutor("0xexecutor");
        payload.setPucHash("0x" + "1".repeat(64));
        payload.setLabId(BigInteger.ONE);

        IntentSubmission submission = new IntentSubmission();
        submission.setMeta(meta);
        submission.setActionPayload(payload);
        submission.setSignature("0xsig");

        return new IntentAuthorizationService.AuthorizationSession(
            "0123456789abcdef0123456789abcdef",
            submission,
            List.of(new IntentAuthorizationService.AllowedCredential("cred-1", List.of("internal"))),
            "challenge",
            "https://app.example/callback",
            Instant.now().plusSeconds(300)
        );
    }
}
