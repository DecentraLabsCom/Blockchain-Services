package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.test.util.ReflectionTestUtils;

import decentralabs.blockchain.service.auth.WebauthnCredentialService.WebauthnCredential;

@ExtendWith(MockitoExtension.class)
class WebauthnCredentialServiceTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Mock
    private ObjectProvider<JdbcTemplate> nullJdbcTemplateProvider;

    private WebauthnCredentialService webauthnCredentialService;

    private static final String TEST_PUC = "testuser@uned.es";
    private static final String TEST_CREDENTIAL_ID = "credential-abc-123";
    private static final String TEST_PUBLIC_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest";
    private static final String TEST_AAGUID = "test-aaguid";

    @BeforeEach
    void setUp() {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        lenient().when(nullJdbcTemplateProvider.getIfAvailable()).thenReturn(null);
        webauthnCredentialService = new WebauthnCredentialService(jdbcTemplateProvider);
        ReflectionTestUtils.setField(webauthnCredentialService, "credentialsTable", "webauthn_credentials");
    }

    @Nested
    @DisplayName("Credential registration tests")
    class RegistrationTests {

        @Test
        @DisplayName("Should register new WebAuthn credential")
        void shouldRegisterNewCredential() {
            webauthnCredentialService.register(
                TEST_PUC,
                TEST_CREDENTIAL_ID,
                TEST_PUBLIC_KEY,
                TEST_AAGUID,
                0L,
                null,
                null,
                null
            );

            ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
            verify(jdbcTemplate).update(
                sqlCaptor.capture(),
                eq(TEST_PUC.trim()),
                eq(TEST_CREDENTIAL_ID.trim()),
                eq(TEST_PUBLIC_KEY),
                eq(TEST_AAGUID),
                eq(0L),
                any(Long.class),
                any(Long.class),
                eq(null),
                eq(null),
                eq(null)
            );

            String sql = sqlCaptor.getValue();
            assertThat(sql).contains("INSERT INTO webauthn_credentials");
            assertThat(sql).contains("ON DUPLICATE KEY UPDATE");
        }

        @Test
        @DisplayName("Should normalize PUC and credential ID during registration")
        void shouldNormalizeDuringRegistration() {
            webauthnCredentialService.register(
                "  " + TEST_PUC + "  ",   // whitespace
                "  " + TEST_CREDENTIAL_ID + "  ",
                TEST_PUBLIC_KEY,
                TEST_AAGUID,
                5L,
                null,
                null,
                null
            );

            verify(jdbcTemplate).update(
                anyString(),
                eq(TEST_PUC),  // should be trimmed
                eq(TEST_CREDENTIAL_ID),  // should be trimmed
                eq(TEST_PUBLIC_KEY),
                eq(TEST_AAGUID),
                eq(5L),
                any(Long.class),
                any(Long.class),
                eq(null),
                eq(null),
                eq(null)
            );
        }

        @Test
        @DisplayName("Should handle null sign count as zero")
        void shouldHandleNullSignCount() {
            webauthnCredentialService.register(
                TEST_PUC,
                TEST_CREDENTIAL_ID,
                TEST_PUBLIC_KEY,
                TEST_AAGUID,
                null,  // null sign count
                null,
                null,
                null
            );

            verify(jdbcTemplate).update(
                anyString(),
                eq(TEST_PUC),
                eq(TEST_CREDENTIAL_ID),
                eq(TEST_PUBLIC_KEY),
                eq(TEST_AAGUID),
                eq(0L),  // should default to 0
                any(Long.class),
                any(Long.class),
                eq(null),
                eq(null),
                eq(null)
            );
        }

        @Test
        @DisplayName("Should reject registration when database persistence fails")
        void shouldRejectRegistrationWhenDatabasePersistenceFails() {
            DataAccessException dbError = new DataAccessResourceFailureException("Connection failed");
            when(jdbcTemplate.update(anyString(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenThrow(dbError);

            assertThatThrownBy(() -> webauthnCredentialService.register(
                TEST_PUC, TEST_CREDENTIAL_ID, TEST_PUBLIC_KEY, TEST_AAGUID, 0L, null, null, null
            ))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("durable persistence failed")
                .hasCause(dbError);
        }
    }

    @Nested
    @DisplayName("Credential revocation tests")
    class RevocationTests {

        @Test
        @DisplayName("Should revoke existing credential")
        void shouldRevokeExistingCredential() {
            webauthnCredentialService.revoke(TEST_PUC, TEST_CREDENTIAL_ID);

            ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
            verify(jdbcTemplate).update(
                sqlCaptor.capture(),
                any(Long.class),  // revoked_at
                any(Long.class),  // updated_at
                eq(TEST_PUC.trim()),
                eq(TEST_CREDENTIAL_ID.trim())
            );

            String sql = sqlCaptor.getValue();
            assertThat(sql).contains("UPDATE webauthn_credentials");
            assertThat(sql).contains("SET active=FALSE");
            assertThat(sql).contains("revoked_at=FROM_UNIXTIME");
        }

        @Test
        @DisplayName("Should normalize PUC and credential ID during revocation")
        void shouldNormalizeDuringRevocation() {
            webauthnCredentialService.revoke(
                "  " + TEST_PUC + "  ",
                "  " + TEST_CREDENTIAL_ID + "  "
            );

            verify(jdbcTemplate).update(
                anyString(),
                any(Long.class),
                any(Long.class),
                eq(TEST_PUC),
                eq(TEST_CREDENTIAL_ID)
            );
        }

        @Test
        @DisplayName("Should reject revocation when database persistence fails")
        void shouldRejectRevocationWhenDatabasePersistenceFails() {
            // First register a credential
            webauthnCredentialService.register(
                TEST_PUC, TEST_CREDENTIAL_ID, TEST_PUBLIC_KEY, TEST_AAGUID, 0L, null, null, null
            );
            
            // Now make DB throw on update (revocation)
            DataAccessException dbError = new DataAccessResourceFailureException("Connection failed");
            when(jdbcTemplate.update(anyString(), any(), any(), any(), any()))
                .thenThrow(dbError);

            assertThatThrownBy(() -> webauthnCredentialService.revoke(TEST_PUC, TEST_CREDENTIAL_ID))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("durable revocation failed")
                .hasCause(dbError);
        }

        @Test
        @DisplayName("Should reject expired-credential revocation when database persistence fails")
        void shouldRejectExpiredRevocationWhenDatabasePersistenceFails() {
            ReflectionTestUtils.setField(webauthnCredentialService, "credentialsMaxAgeDays", 365L);
            DataAccessException dbError = new DataAccessResourceFailureException("Connection failed");
            when(jdbcTemplate.update(anyString(), any(), any(), any())).thenThrow(dbError);

            assertThatThrownBy(() -> webauthnCredentialService.revokeExpiredCredentials())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expired-credential revocation failed")
                .hasCause(dbError);
        }
    }

    @Nested
    @DisplayName("Signature counter tests")
    class SignCountTests {

        @Test
        @DisplayName("Should advance the counter with a durable compare-and-set update")
        void shouldAdvanceSignCountDurably() {
            WebauthnCredential credential = new WebauthnCredential(
                TEST_CREDENTIAL_ID, TEST_PUBLIC_KEY, TEST_AAGUID, 5L, true, 0L, 0L, null, null, null, null
            );
            @SuppressWarnings("unchecked")
            var inMemory = (java.util.Map<String, WebauthnCredential>) ReflectionTestUtils
                .getField(webauthnCredentialService, "inMemoryCredentials");
            inMemory.put(TEST_PUC + ":" + TEST_CREDENTIAL_ID, credential);
            when(jdbcTemplate.query(
                anyString(), any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<ResultSetExtractor<Object>>any()
            )).thenReturn(Optional.of(credential));
            when(jdbcTemplate.update(anyString(), any(), any(), any(), any(), any())).thenReturn(1);

            assertThat(webauthnCredentialService.advanceSignCount(TEST_PUC, TEST_CREDENTIAL_ID, 6L)).isTrue();
            assertThat(webauthnCredentialService.findCredential(TEST_PUC, TEST_CREDENTIAL_ID).orElseThrow().getSignCount())
                .isEqualTo(6L);
            verify(jdbcTemplate).update(
                argThat(sql -> sql.contains("WHERE puc=? AND credential_id=? AND active=TRUE AND sign_count=?")),
                eq(6L), any(Long.class), eq(TEST_PUC), eq(TEST_CREDENTIAL_ID), eq(5L)
            );
        }

        @Test
        @DisplayName("Should reject a non-increasing non-zero counter")
        void shouldRejectCounterReplay() {
            WebauthnCredential credential = new WebauthnCredential(
                TEST_CREDENTIAL_ID, TEST_PUBLIC_KEY, TEST_AAGUID, 5L, true, 0L, 0L, null, null, null, null
            );
            @SuppressWarnings("unchecked")
            var inMemory = (java.util.Map<String, WebauthnCredential>) ReflectionTestUtils
                .getField(webauthnCredentialService, "inMemoryCredentials");
            inMemory.put(TEST_PUC + ":" + TEST_CREDENTIAL_ID, credential);
            when(jdbcTemplate.query(
                anyString(), any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<ResultSetExtractor<Object>>any()
            )).thenReturn(Optional.of(credential));

            assertThat(webauthnCredentialService.advanceSignCount(TEST_PUC, TEST_CREDENTIAL_ID, 5L)).isFalse();
            verify(jdbcTemplate, never()).update(anyString(), any(), any(), any(), any(), any());
        }
    }

    @Nested
    @DisplayName("Credential lookup tests")
    class LookupTests {

        @Test
        @DisplayName("Should find active credential")
        void shouldFindActiveCredential() {
            WebauthnCredential expected = new WebauthnCredential(
                TEST_CREDENTIAL_ID,
                TEST_PUBLIC_KEY,
                TEST_AAGUID,
                10L,
                true,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                null,
                null,
                null
            );

            when(jdbcTemplate.query(
                anyString(),
                any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<ResultSetExtractor<Object>>any()
            )).thenReturn(Optional.of(expected));

            Optional<WebauthnCredential> result = webauthnCredentialService.findCredential(TEST_PUC, TEST_CREDENTIAL_ID);

            assertThat(result).isPresent();
            assertThat(result.get().getCredentialId()).isEqualTo(TEST_CREDENTIAL_ID);
            assertThat(result.get().isActive()).isTrue();
        }

        @Test
        @DisplayName("Should return empty for non-existent credential")
        void shouldReturnEmptyForNonExistentCredential() {
            when(jdbcTemplate.query(
                anyString(),
                any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<ResultSetExtractor<Object>>any()
            )).thenReturn(Optional.empty());

            Optional<WebauthnCredential> result = webauthnCredentialService.findCredential(TEST_PUC, "unknown-cred");

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should check if credential is active")
        void shouldCheckIfCredentialIsActive() {
            WebauthnCredential activeCred = new WebauthnCredential(
                TEST_CREDENTIAL_ID, TEST_PUBLIC_KEY, TEST_AAGUID, 0L, true, 0L, 0L, null, null, null, null
            );
            when(jdbcTemplate.query(
                anyString(),
                any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<ResultSetExtractor<Object>>any()
            )).thenReturn(Optional.of(activeCred));

            boolean isActive = webauthnCredentialService.isCredentialActive(TEST_PUC, TEST_CREDENTIAL_ID);

            assertThat(isActive).isTrue();
        }

        @Test
        @DisplayName("Should return false for revoked credential")
        void shouldReturnFalseForRevokedCredential() {
            WebauthnCredential revokedCred = new WebauthnCredential(
                TEST_CREDENTIAL_ID, TEST_PUBLIC_KEY, TEST_AAGUID, 0L, false, 0L, 0L, Instant.now().getEpochSecond(), null, null, null
            );
            when(jdbcTemplate.query(
                anyString(),
                any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<ResultSetExtractor<Object>>any()
            )).thenReturn(Optional.of(revokedCred));

            boolean isActive = webauthnCredentialService.isCredentialActive(TEST_PUC, TEST_CREDENTIAL_ID);

            assertThat(isActive).isFalse();
        }

        @Test
        @DisplayName("Should return false when credential not found")
        void shouldReturnFalseWhenCredentialNotFound() {
            when(jdbcTemplate.query(
                anyString(),
                any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<ResultSetExtractor<Object>>any()
            )).thenReturn(Optional.empty());

            boolean isActive = webauthnCredentialService.isCredentialActive(TEST_PUC, "unknown");

            assertThat(isActive).isFalse();
        }

        @Test
        @DisplayName("Should read the durable credential after registration")
        void shouldReadDurableCredentialAfterRegistration() {
            webauthnCredentialService.register(
                TEST_PUC, TEST_CREDENTIAL_ID, TEST_PUBLIC_KEY, TEST_AAGUID, 10L, null, null, null
            );

            WebauthnCredential expected = new WebauthnCredential(
                TEST_CREDENTIAL_ID,
                TEST_PUBLIC_KEY,
                TEST_AAGUID,
                10L,
                true,
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                null,
                null,
                null,
                null
            );
            when(jdbcTemplate.query(
                anyString(),
                any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<ResultSetExtractor<Object>>any()
            )).thenReturn(Optional.of(expected));

            Optional<WebauthnCredential> result = webauthnCredentialService.findCredential(TEST_PUC, TEST_CREDENTIAL_ID);

            assertThat(result).isPresent();
            assertThat(result.get().getCredentialId()).isEqualTo(TEST_CREDENTIAL_ID);
        }
    }

    @Nested
    @DisplayName("Get all credentials tests")
    class GetAllCredentialsTests {

        @Test
        @DisplayName("Should return all credentials for PUC")
        void shouldReturnAllCredentialsForPuc() {
            List<WebauthnCredential> expected = List.of(
                new WebauthnCredential("cred1", TEST_PUBLIC_KEY, TEST_AAGUID, 0L, true, 0L, 0L, null, null, null, null),
                new WebauthnCredential("cred2", TEST_PUBLIC_KEY, TEST_AAGUID, 5L, true, 0L, 0L, null, null, null, null),
                new WebauthnCredential("cred3", TEST_PUBLIC_KEY, TEST_AAGUID, 0L, false, 0L, 0L, 0L, null, null, null)
            );

            when(jdbcTemplate.query(
                anyString(),
                any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<RowMapper<WebauthnCredential>>any()
            )).thenReturn(expected);

            List<WebauthnCredential> result = webauthnCredentialService.getCredentials(TEST_PUC);

            assertThat(result).hasSize(3);
            assertThat(result.get(0).getCredentialId()).isEqualTo("cred1");
            assertThat(result.get(2).isActive()).isFalse();
        }

        @Test
        @DisplayName("Should return empty list when no credentials")
        void shouldReturnEmptyListWhenNoCredentials() {
            when(jdbcTemplate.query(
                anyString(),
                any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<RowMapper<WebauthnCredential>>any()
            )).thenReturn(List.of());

            List<WebauthnCredential> result = webauthnCredentialService.getCredentials(TEST_PUC);

            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("Input normalization tests")
    class NormalizationTests {

        @Test
        @DisplayName("Should handle null PUC as empty string")
        void shouldHandleNullPucAsEmptyString() {
            when(jdbcTemplate.query(
                anyString(),
                any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<ResultSetExtractor<Object>>any()
            )).thenReturn(Optional.empty());

            Optional<WebauthnCredential> result = webauthnCredentialService.findCredential(null, TEST_CREDENTIAL_ID);

            assertThat(result).isEmpty();
            // Should not throw NPE
        }

        @Test
        @DisplayName("Should handle null credential ID as empty string")
        void shouldHandleNullCredentialIdAsEmptyString() {
            when(jdbcTemplate.query(
                anyString(),
                any(PreparedStatementSetter.class),
                org.mockito.ArgumentMatchers.<ResultSetExtractor<Object>>any()
            )).thenReturn(Optional.empty());

            Optional<WebauthnCredential> result = webauthnCredentialService.findCredential(TEST_PUC, null);

            assertThat(result).isEmpty();
            // Should not throw NPE
        }
    }

    @Nested
    @DisplayName("In-memory only mode tests (no database)")
    class InMemoryOnlyModeTests {

        private WebauthnCredentialService inMemoryOnlyService;

        @BeforeEach
        void setUpInMemoryMode() {
            inMemoryOnlyService = new WebauthnCredentialService(nullJdbcTemplateProvider);
            ReflectionTestUtils.setField(inMemoryOnlyService, "credentialsTable", "webauthn_credentials");
            ReflectionTestUtils.setField(inMemoryOnlyService, "databaseRequired", false);
        }

        @Test
        @DisplayName("Should reject registration without a database unless explicitly opted into memory-only mode")
        void shouldRejectRegistrationWithoutDatabaseByDefault() {
            ReflectionTestUtils.setField(inMemoryOnlyService, "databaseRequired", true);

            assertThatThrownBy(() -> inMemoryOnlyService.register(
                TEST_PUC, TEST_CREDENTIAL_ID, TEST_PUBLIC_KEY, TEST_AAGUID, 0L, null, null, null
            ))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("database is required");
        }

        @Test
        @DisplayName("Should register credential in memory when no database available")
        void shouldRegisterCredentialInMemory() {
            inMemoryOnlyService.register(
                TEST_PUC,
                TEST_CREDENTIAL_ID,
                TEST_PUBLIC_KEY,
                TEST_AAGUID,
                0L,
                null,
                null,
                null
            );

            // Verify credential can be found
            Optional<WebauthnCredential> result = inMemoryOnlyService.findCredential(TEST_PUC, TEST_CREDENTIAL_ID);
            
            assertThat(result).isPresent();
            assertThat(result.get().getCredentialId()).isEqualTo(TEST_CREDENTIAL_ID);
            assertThat(result.get().getPublicKey()).isEqualTo(TEST_PUBLIC_KEY);
            assertThat(result.get().isActive()).isTrue();
        }

        @Test
        @DisplayName("Should revoke credential in memory when no database available")
        void shouldRevokeCredentialInMemory() {
            // Register first
            inMemoryOnlyService.register(
                TEST_PUC,
                TEST_CREDENTIAL_ID,
                TEST_PUBLIC_KEY,
                TEST_AAGUID,
                0L,
                null,
                null,
                null
            );

            // Revoke
            inMemoryOnlyService.revoke(TEST_PUC, TEST_CREDENTIAL_ID);

            // Verify credential is inactive
            Optional<WebauthnCredential> result = inMemoryOnlyService.findCredential(TEST_PUC, TEST_CREDENTIAL_ID);
            
            assertThat(result).isPresent();
            assertThat(result.get().isActive()).isFalse();
            assertThat(result.get().getRevokedAt()).isNotNull();
        }

        @Test
        @DisplayName("Should return empty when credential not found in memory")
        void shouldReturnEmptyWhenCredentialNotFound() {
            Optional<WebauthnCredential> result = inMemoryOnlyService.findCredential(TEST_PUC, "non-existent");
            
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should list all credentials for PUC from memory")
        void shouldListAllCredentialsFromMemory() {
            // Register multiple credentials
            inMemoryOnlyService.register(TEST_PUC, "cred1", TEST_PUBLIC_KEY, TEST_AAGUID, 0L, null, null, null);
            inMemoryOnlyService.register(TEST_PUC, "cred2", TEST_PUBLIC_KEY, TEST_AAGUID, 5L, null, null, null);
            inMemoryOnlyService.register("other@uned.es", "cred3", TEST_PUBLIC_KEY, TEST_AAGUID, 0L, null, null, null);

            List<WebauthnCredential> result = inMemoryOnlyService.getCredentials(TEST_PUC);
            
            assertThat(result).hasSize(2);
            assertThat(result).extracting((WebauthnCredential credential) -> credential.getCredentialId())
                .containsExactlyInAnyOrder("cred1", "cred2");
        }

        @Test
        @DisplayName("Should check credential active status correctly in memory")
        void shouldCheckCredentialActiveStatusInMemory() {
            inMemoryOnlyService.register(TEST_PUC, TEST_CREDENTIAL_ID, TEST_PUBLIC_KEY, TEST_AAGUID, 0L, null, null, null);
            
            assertThat(inMemoryOnlyService.isCredentialActive(TEST_PUC, TEST_CREDENTIAL_ID)).isTrue();
            
            inMemoryOnlyService.revoke(TEST_PUC, TEST_CREDENTIAL_ID);
            
            assertThat(inMemoryOnlyService.isCredentialActive(TEST_PUC, TEST_CREDENTIAL_ID)).isFalse();
        }

        @Test
        @DisplayName("Should return false for non-existent credential active check")
        void shouldReturnFalseForNonExistentCredentialActiveCheck() {
            assertThat(inMemoryOnlyService.isCredentialActive(TEST_PUC, "unknown")).isFalse();
        }

        @Test
        @DisplayName("Should not call database when in memory-only mode")
        void shouldNotCallDatabaseInMemoryOnlyMode() {
            inMemoryOnlyService.register(TEST_PUC, TEST_CREDENTIAL_ID, TEST_PUBLIC_KEY, TEST_AAGUID, 0L, null, null, null);
            inMemoryOnlyService.findCredential(TEST_PUC, TEST_CREDENTIAL_ID);
            inMemoryOnlyService.getCredentials(TEST_PUC);
            inMemoryOnlyService.revoke(TEST_PUC, TEST_CREDENTIAL_ID);

            // Verify JdbcTemplate was never called (since it's null in inMemoryOnlyService)
            // The jdbcTemplate mock is used by webauthnCredentialService, not by inMemoryOnlyService
            // So we just verify the service works without DB - no explicit verification needed
            // The fact that we got here without exceptions proves it works
            assertThat(inMemoryOnlyService.isDatabaseAvailable()).isFalse();
        }
    }
}
