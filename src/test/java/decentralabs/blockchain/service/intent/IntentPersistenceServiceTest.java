package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.test.util.ReflectionTestUtils;

import decentralabs.blockchain.dto.intent.IntentStatus;

@ExtendWith(MockitoExtension.class)
class IntentPersistenceServiceTest {

    @Mock
    private DataSource dataSource;

    @Mock
    private JdbcTemplate jdbcTemplate;

    private IntentPersistenceService service;

    @BeforeEach
    void setUp() {
        service = new IntentPersistenceService(dataSource);
        ReflectionTestUtils.setField(service, "jdbcTemplate", jdbcTemplate);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should handle null datasource gracefully")
        void shouldHandleNullDatasource() {
            IntentPersistenceService nullService = new IntentPersistenceService(null);
            // Should not throw, operations should be no-ops
            assertThat(nullService).isNotNull();
        }
    }

    @Nested
    @DisplayName("Upsert Tests")
    class UpsertTests {

        @Test
        @DisplayName("Should upsert intent record with all fields")
        void shouldUpsertIntentRecordWithAllFields() {
            IntentRecord record = createTestRecord("req-001", "LAB_ADD", "github");
            record.setStatus(IntentStatus.EXECUTED);
            record.setLabId("lab-42");
            record.setTxHash("0xabc123");
            record.setBlockNumber(12345L);
            record.setNonce(1L);
            record.setExpiresAt(System.currentTimeMillis() / 1000 + 3600);
            record.setPayloadJson("{\"test\":true}");

            service.upsert(record);

            verify(jdbcTemplate).update(
                anyString(),
                eq("req-001"),
                eq("executed"),
                eq("LAB_ADD"),
                eq("github"),
                eq("lab-42"),
                any(), // reservation key
                eq("0xabc123"),
                eq(12345L),
                any(), // error
                any(), // reason
                any(Timestamp.class), // updated_at
                any(Timestamp.class), // created_at
                eq(1L),
                any(), // expires_at
                eq("{\"test\":true}")
            );
        }

        @Test
        @DisplayName("Should skip upsert when jdbcTemplate is null")
        void shouldSkipUpsertWhenJdbcTemplateIsNull() {
            IntentPersistenceService nullService = new IntentPersistenceService(null);
            IntentRecord record = createTestRecord("req-002", "LAB_UPDATE", "web");

            // Should not throw
            nullService.upsert(record);
        }

        @Test
        @DisplayName("Should handle database exception gracefully")
        void shouldHandleDatabaseExceptionGracefully() {
            IntentRecord record = createTestRecord("req-003", "RESERVATION", "api");
            when(jdbcTemplate.update(anyString(), any(Object[].class)))
                .thenThrow(new RuntimeException("Connection failed"));

            // Should not throw
            service.upsert(record);
        }

        @Test
        @DisplayName("Should upsert with minimal fields")
        void shouldUpsertWithMinimalFields() {
            IntentRecord record = createTestRecord("req-004", "CANCEL", "cli");

            service.upsert(record);

            verify(jdbcTemplate).update(anyString(), any(Object[].class));
        }
    }

    @Nested
    @DisplayName("FindByRequestId Tests")
    class FindByRequestIdTests {

        @Test
        @DisplayName("Should return empty when jdbcTemplate is null")
        void shouldReturnEmptyWhenJdbcTemplateIsNull() {
            IntentPersistenceService nullService = new IntentPersistenceService(null);

            Optional<IntentRecord> result = nullService.findByRequestId("any-id");

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should find existing record by request ID")
        @SuppressWarnings("unchecked")
        void shouldFindExistingRecordByRequestId() throws Exception {
            String requestId = "req-find-001";
            IntentRecord expectedRecord = createTestRecord(requestId, "LAB_ADD", "github");
            expectedRecord.setStatus(IntentStatus.EXECUTED);

            when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq(requestId)))
                .thenReturn(List.of(expectedRecord));

            Optional<IntentRecord> result = service.findByRequestId(requestId);

            assertThat(result).isPresent();
            assertThat(result.get().getRequestId()).isEqualTo(requestId);
        }

        @Test
        @DisplayName("Should return empty when record not found")
        @SuppressWarnings("unchecked")
        void shouldReturnEmptyWhenRecordNotFound() {
            when(jdbcTemplate.query(anyString(), any(RowMapper.class), anyString()))
                .thenReturn(Collections.emptyList());

            Optional<IntentRecord> result = service.findByRequestId("nonexistent-id");

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should handle query exception gracefully")
        @SuppressWarnings("unchecked")
        void shouldHandleQueryExceptionGracefully() {
            when(jdbcTemplate.query(anyString(), any(RowMapper.class), anyString()))
                .thenThrow(new RuntimeException("Query failed"));

            Optional<IntentRecord> result = service.findByRequestId("error-id");

            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("Status Wire Value Tests")
    class StatusWireValueTests {

        @Test
        @DisplayName("Should use correct wire value for QUEUED status")
        void shouldUseCorrectWireValueForPending() {
            IntentRecord record = createTestRecord("req-status-001", "LAB_ADD", "test");
            record.setStatus(IntentStatus.QUEUED);

            service.upsert(record);

            ArgumentCaptor<Object[]> captor = ArgumentCaptor.forClass(Object[].class);
            verify(jdbcTemplate).update(anyString(), captor.capture());
            
            Object[] args = captor.getValue();
            assertThat(args[1]).isEqualTo("queued");
        }

        @Test
        @DisplayName("Should use correct wire value for EXECUTED status")
        void shouldUseCorrectWireValueForConfirmed() {
            IntentRecord record = createTestRecord("req-status-002", "LAB_ADD", "test");
            record.setStatus(IntentStatus.EXECUTED);

            service.upsert(record);

            ArgumentCaptor<Object[]> captor = ArgumentCaptor.forClass(Object[].class);
            verify(jdbcTemplate).update(anyString(), captor.capture());
            
            Object[] args = captor.getValue();
            assertThat(args[1]).isEqualTo("executed");
        }

        @Test
        @DisplayName("Should use correct wire value for FAILED status")
        void shouldUseCorrectWireValueForFailed() {
            IntentRecord record = createTestRecord("req-status-003", "LAB_ADD", "test");
            record.setStatus(IntentStatus.FAILED);

            service.upsert(record);

            ArgumentCaptor<Object[]> captor = ArgumentCaptor.forClass(Object[].class);
            verify(jdbcTemplate).update(anyString(), captor.capture());
            
            Object[] args = captor.getValue();
            assertThat(args[1]).isEqualTo("failed");
        }
    }

    private IntentRecord createTestRecord(String requestId, String action, String provider) {
        IntentRecord record = new IntentRecord(requestId, action, provider);
        record.setStatus(IntentStatus.QUEUED);
        record.setCreatedAt(Instant.now());
        record.setUpdatedAt(Instant.now());
        return record;
    }
}
