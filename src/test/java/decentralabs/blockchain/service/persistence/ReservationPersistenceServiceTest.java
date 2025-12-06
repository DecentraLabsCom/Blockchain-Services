package decentralabs.blockchain.service.persistence;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Timestamp;
import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.ResultSetExtractor;

@ExtendWith(MockitoExtension.class)
class ReservationPersistenceServiceTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    private ReservationPersistenceService service;

    private static final String TX_HASH = "0xabc123def456";
    private static final String WALLET_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
    private static final String LAB_ID = "42";
    private static final Instant START_TIME = Instant.parse("2024-01-15T10:00:00Z");
    private static final Instant END_TIME = Instant.parse("2024-01-15T12:00:00Z");
    private static final String STATUS = "CONFIRMED";

    @BeforeEach
    void setUp() {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        service = new ReservationPersistenceService(jdbcTemplateProvider);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should handle missing JdbcTemplate gracefully")
        void shouldHandleMissingJdbcTemplateGracefully() {
            when(jdbcTemplateProvider.getIfAvailable()).thenReturn(null);
            ReservationPersistenceService nullService = new ReservationPersistenceService(jdbcTemplateProvider);

            // Should not throw when upserting without template
            nullService.upsertReservation(TX_HASH, WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);
        }
    }

    @Nested
    @DisplayName("Upsert Reservation Tests")
    class UpsertReservationTests {

        @Test
        @DisplayName("Should skip upsert when jdbcTemplate is null")
        void shouldSkipUpsertWhenJdbcTemplateIsNull() {
            when(jdbcTemplateProvider.getIfAvailable()).thenReturn(null);
            ReservationPersistenceService nullService = new ReservationPersistenceService(jdbcTemplateProvider);

            nullService.upsertReservation(TX_HASH, WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);

            // No interaction expected
        }

        @Test
        @DisplayName("Should skip upsert when txHash is null")
        void shouldSkipUpsertWhenTxHashIsNull() {
            service.upsertReservation(null, WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);

            verify(jdbcTemplate, never()).update(anyString(), any(Object[].class));
        }

        @Test
        @DisplayName("Should skip upsert when txHash is blank")
        void shouldSkipUpsertWhenTxHashIsBlank() {
            service.upsertReservation("   ", WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);

            verify(jdbcTemplate, never()).update(anyString(), any(Object[].class));
        }

        @Test
        @DisplayName("Should skip upsert when wallet is null")
        void shouldSkipUpsertWhenWalletIsNull() {
            service.upsertReservation(TX_HASH, null, LAB_ID, START_TIME, END_TIME, STATUS);

            verify(jdbcTemplate, never()).update(anyString(), any(Object[].class));
        }

        @Test
        @DisplayName("Should skip upsert when wallet is blank")
        void shouldSkipUpsertWhenWalletIsBlank() {
            service.upsertReservation(TX_HASH, "   ", LAB_ID, START_TIME, END_TIME, STATUS);

            verify(jdbcTemplate, never()).update(anyString(), any(Object[].class));
        }

        @Test
        @DisplayName("Should upsert reservation with existing user")
        @SuppressWarnings("unchecked")
        void shouldUpsertReservationWithExistingUser() {
            Long userId = 123L;
            when(jdbcTemplate.query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class)))
                .thenReturn(userId);

            service.upsertReservation(TX_HASH, WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);

            verify(jdbcTemplate).update(
                anyString(),
                eq(TX_HASH),
                eq(userId),
                eq(WALLET_ADDRESS),
                eq(LAB_ID),
                any(Timestamp.class),
                any(Timestamp.class),
                eq(STATUS)
            );
        }

        @Test
        @DisplayName("Should create user when not found")
        @SuppressWarnings("unchecked")
        void shouldCreateUserWhenNotFound() {
            Long newUserId = 456L;
            // First query returns null (user not found), second returns the new ID
            when(jdbcTemplate.query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class)))
                .thenReturn(null, newUserId);

            service.upsertReservation(TX_HASH, WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);

            // Should insert new user
            verify(jdbcTemplate, times(1)).update(
                eq("INSERT INTO auth_users (wallet_address, created_at, updated_at, is_active) VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)"),
                eq(WALLET_ADDRESS)
            );
        }

        @Test
        @DisplayName("Should upsert with null times")
        @SuppressWarnings("unchecked")
        void shouldUpsertWithNullTimes() {
            Long userId = 789L;
            when(jdbcTemplate.query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class)))
                .thenReturn(userId);

            service.upsertReservation(TX_HASH, WALLET_ADDRESS, LAB_ID, null, null, STATUS);

            verify(jdbcTemplate).update(
                anyString(),
                eq(TX_HASH),
                eq(userId),
                eq(WALLET_ADDRESS),
                eq(LAB_ID),
                eq(null), // start time
                eq(null), // end time
                eq(STATUS)
            );
        }

        @Test
        @DisplayName("Should handle DataAccessException gracefully")
        @SuppressWarnings("unchecked")
        void shouldHandleDataAccessExceptionGracefully() {
            when(jdbcTemplate.query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class)))
                .thenThrow(new DataAccessException("Table not found") {});

            // Should not throw
            service.upsertReservation(TX_HASH, WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);
        }

        @Test
        @DisplayName("Should only log warning once for missing table")
        @SuppressWarnings("unchecked")
        void shouldOnlyLogWarningOnceForMissingTable() {
            when(jdbcTemplate.query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class)))
                .thenThrow(new DataAccessException("Table not found") {});

            // Multiple calls should only trigger warning once
            service.upsertReservation(TX_HASH, WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);
            service.upsertReservation(TX_HASH + "2", WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);

            // Both should skip silently after first failure (tableMissing flag set)
        }

        @Test
        @DisplayName("Should handle generic exception gracefully")
        @SuppressWarnings("unchecked")
        void shouldHandleGenericExceptionGracefully() {
            Long userId = 111L;
            when(jdbcTemplate.query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class)))
                .thenReturn(userId);
            when(jdbcTemplate.update(anyString(), any(Object[].class)))
                .thenThrow(new RuntimeException("Connection lost"));

            // Should not throw
            service.upsertReservation(TX_HASH, WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);
        }
    }

    @Nested
    @DisplayName("Find Or Create User Tests")
    class FindOrCreateUserTests {

        @SuppressWarnings("unchecked")
        @Test
        @DisplayName("Should return null for null wallet in findOrCreateUser")
        void shouldReturnNullForNullWallet() {
            // Upsert with null wallet should be skipped, no user lookup
            service.upsertReservation(TX_HASH, null, LAB_ID, START_TIME, END_TIME, STATUS);

            verify(jdbcTemplate, never()).query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class));
        }

        @SuppressWarnings("unchecked")
        @Test
        @DisplayName("Should return null for blank wallet in findOrCreateUser")
        void shouldReturnNullForBlankWallet() {
            service.upsertReservation(TX_HASH, "   ", LAB_ID, START_TIME, END_TIME, STATUS);

            verify(jdbcTemplate, never()).query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class));
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty string txHash")
        void shouldHandleEmptyStringTxHash() {
            service.upsertReservation("", WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, STATUS);

            verify(jdbcTemplate, never()).update(anyString(), any(Object[].class));
        }

        @Test
        @DisplayName("Should handle null labId")
        @SuppressWarnings("unchecked")
        void shouldHandleNullLabId() {
            Long userId = 222L;
            when(jdbcTemplate.query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class)))
                .thenReturn(userId);

            service.upsertReservation(TX_HASH, WALLET_ADDRESS, null, START_TIME, END_TIME, STATUS);

            verify(jdbcTemplate).update(
                anyString(),
                eq(TX_HASH),
                eq(userId),
                eq(WALLET_ADDRESS),
                eq(null), // lab_id
                any(Timestamp.class),
                any(Timestamp.class),
                eq(STATUS)
            );
        }

        @Test
        @DisplayName("Should handle null status")
        @SuppressWarnings("unchecked")
        void shouldHandleNullStatus() {
            Long userId = 333L;
            when(jdbcTemplate.query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class)))
                .thenReturn(userId);

            service.upsertReservation(TX_HASH, WALLET_ADDRESS, LAB_ID, START_TIME, END_TIME, null);

            verify(jdbcTemplate).update(
                anyString(),
                eq(TX_HASH),
                eq(userId),
                eq(WALLET_ADDRESS),
                eq(LAB_ID),
                any(Timestamp.class),
                any(Timestamp.class),
                eq(null) // status
            );
        }
    }
}
