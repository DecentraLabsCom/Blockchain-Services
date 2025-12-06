package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import decentralabs.blockchain.dto.intent.IntentStatus;
import decentralabs.blockchain.service.intent.IntentOnChainExecutor.ExecutionResult;

/**
 * Unit tests for IntentExecutionService.
 * Tests the scheduled processing of queued intents.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("IntentExecutionService Tests")
class IntentExecutionServiceTest {

    @Mock
    private IntentService intentService;
    
    @Mock
    private IntentOnChainExecutor onChainExecutor;
    
    @InjectMocks
    private IntentExecutionService executionService;

    @Captor
    private ArgumentCaptor<IntentRecord> recordCaptor;

    @Captor
    private ArgumentCaptor<String> reasonCaptor;

    // =========================================================================
    // EMPTY QUEUE TESTS
    // =========================================================================
    
    @Nested
    @DisplayName("Empty Queue Handling")
    class EmptyQueueTests {
        
        @Test
        @DisplayName("Should do nothing when queue is empty")
        void shouldDoNothingWhenQueueIsEmpty() throws Exception {
            // Given
            when(intentService.getQueuedIntents()).thenReturn(Collections.emptyMap());
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(intentService).getQueuedIntents();
            verifyNoInteractions(onChainExecutor);
            verify(intentService, never()).markInProgress(any());
            verify(intentService, never()).markExecuted(any(), any(), any(), any(), any());
            verify(intentService, never()).markFailed(any(), any());
        }
        
        @Test
        @DisplayName("Should skip non-QUEUED intents")
        void shouldSkipNonQueuedIntents() throws Exception {
            // Given
            Map<String, IntentRecord> intents = new HashMap<>();
            
            IntentRecord inProgressIntent = createIntentRecord("req-1", IntentStatus.IN_PROGRESS);
            IntentRecord executedIntent = createIntentRecord("req-2", IntentStatus.EXECUTED);
            IntentRecord failedIntent = createIntentRecord("req-3", IntentStatus.FAILED);
            
            intents.put("req-1", inProgressIntent);
            intents.put("req-2", executedIntent);
            intents.put("req-3", failedIntent);
            
            when(intentService.getQueuedIntents()).thenReturn(intents);
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verifyNoInteractions(onChainExecutor);
            verify(intentService, never()).markInProgress(any());
        }
    }

    // =========================================================================
    // EXPIRATION TESTS
    // =========================================================================
    
    @Nested
    @DisplayName("Intent Expiration")
    class ExpirationTests {
        
        @Test
        @DisplayName("Should mark expired intents as failed")
        void shouldMarkExpiredIntentsAsFailed() throws Exception {
            // Given
            IntentRecord expiredIntent = createIntentRecord("req-expired", IntentStatus.QUEUED);
            expiredIntent.setExpiresAt(Instant.now().getEpochSecond() - 100); // Expired 100 seconds ago
            
            Map<String, IntentRecord> intents = Map.of("req-expired", expiredIntent);
            when(intentService.getQueuedIntents()).thenReturn(intents);
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(intentService).markFailed(eq(expiredIntent), eq("expired"));
            verify(intentService, never()).markInProgress(any());
            verifyNoInteractions(onChainExecutor);
        }
        
        @Test
        @DisplayName("Should process non-expired intents")
        void shouldProcessNonExpiredIntents() throws Exception {
            // Given
            IntentRecord validIntent = createIntentRecord("req-valid", IntentStatus.QUEUED);
            validIntent.setExpiresAt(Instant.now().getEpochSecond() + 3600); // Expires in 1 hour
            
            Map<String, IntentRecord> intents = Map.of("req-valid", validIntent);
            when(intentService.getQueuedIntents()).thenReturn(intents);
            when(onChainExecutor.execute(validIntent))
                .thenReturn(new ExecutionResult(true, "0xabc123", 12345L, "lab-1", "key-1", null));
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(intentService).markInProgress(validIntent);
            verify(onChainExecutor).execute(validIntent);
            verify(intentService).markExecuted(validIntent, "0xabc123", 12345L, "lab-1", "key-1");
        }
        
        @Test
        @DisplayName("Should process intents with null expiration")
        void shouldProcessIntentsWithNullExpiration() throws Exception {
            // Given
            IntentRecord noExpiryIntent = createIntentRecord("req-no-expiry", IntentStatus.QUEUED);
            noExpiryIntent.setExpiresAt(null);
            
            Map<String, IntentRecord> intents = Map.of("req-no-expiry", noExpiryIntent);
            when(intentService.getQueuedIntents()).thenReturn(intents);
            when(onChainExecutor.execute(noExpiryIntent))
                .thenReturn(new ExecutionResult(true, "0xdef456", 12346L, "lab-2", "key-2", null));
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(intentService).markInProgress(noExpiryIntent);
            verify(onChainExecutor).execute(noExpiryIntent);
            verify(intentService).markExecuted(noExpiryIntent, "0xdef456", 12346L, "lab-2", "key-2");
        }
    }

    // =========================================================================
    // SUCCESSFUL EXECUTION TESTS
    // =========================================================================
    
    @Nested
    @DisplayName("Successful Execution")
    class SuccessfulExecutionTests {
        
        @Test
        @DisplayName("Should mark intent as executed on success")
        void shouldMarkIntentAsExecutedOnSuccess() throws Exception {
            // Given
            IntentRecord intent = createIntentRecord("req-success", IntentStatus.QUEUED);
            intent.setExpiresAt(Instant.now().getEpochSecond() + 3600);
            
            Map<String, IntentRecord> intents = Map.of("req-success", intent);
            when(intentService.getQueuedIntents()).thenReturn(intents);
            
            ExecutionResult result = new ExecutionResult(true, "0xtxhash", 99999L, "lab-id-123", "res-key-456", null);
            when(onChainExecutor.execute(intent)).thenReturn(result);
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(intentService).markInProgress(intent);
            verify(intentService).markExecuted(intent, "0xtxhash", 99999L, "lab-id-123", "res-key-456");
            verify(intentService, never()).markFailed(any(), any());
        }
        
        @Test
        @DisplayName("Should process multiple intents sequentially")
        void shouldProcessMultipleIntentsSequentially() throws Exception {
            // Given
            IntentRecord intent1 = createIntentRecord("req-1", IntentStatus.QUEUED);
            IntentRecord intent2 = createIntentRecord("req-2", IntentStatus.QUEUED);
            IntentRecord intent3 = createIntentRecord("req-3", IntentStatus.QUEUED);
            
            Map<String, IntentRecord> intents = new HashMap<>();
            intents.put("req-1", intent1);
            intents.put("req-2", intent2);
            intents.put("req-3", intent3);
            
            when(intentService.getQueuedIntents()).thenReturn(intents);
            when(onChainExecutor.execute(any()))
                .thenReturn(new ExecutionResult(true, "0xhash", 100L, "lab", "key", null));
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(onChainExecutor, times(3)).execute(any());
            verify(intentService, times(3)).markInProgress(any());
            verify(intentService, times(3)).markExecuted(any(), any(), any(), any(), any());
        }
    }

    // =========================================================================
    // FAILED EXECUTION TESTS
    // =========================================================================
    
    @Nested
    @DisplayName("Failed Execution")
    class FailedExecutionTests {
        
        @Test
        @DisplayName("Should mark intent as failed when execution returns failure")
        void shouldMarkIntentAsFailedWhenExecutionFails() throws Exception {
            // Given
            IntentRecord intent = createIntentRecord("req-fail", IntentStatus.QUEUED);
            
            Map<String, IntentRecord> intents = Map.of("req-fail", intent);
            when(intentService.getQueuedIntents()).thenReturn(intents);
            
            ExecutionResult failResult = new ExecutionResult(false, null, null, null, null, "unsupported_action");
            when(onChainExecutor.execute(intent)).thenReturn(failResult);
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(intentService).markInProgress(intent);
            verify(intentService).markFailed(intent, "unsupported_action");
            verify(intentService, never()).markExecuted(any(), any(), any(), any(), any());
        }
        
        @Test
        @DisplayName("Should mark intent as failed when exception occurs")
        void shouldMarkIntentAsFailedWhenExceptionOccurs() throws Exception {
            // Given
            IntentRecord intent = createIntentRecord("req-exception", IntentStatus.QUEUED);
            
            Map<String, IntentRecord> intents = Map.of("req-exception", intent);
            when(intentService.getQueuedIntents()).thenReturn(intents);
            when(onChainExecutor.execute(intent)).thenThrow(new RuntimeException("Network timeout"));
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(intentService).markInProgress(intent);
            verify(intentService).markFailed(recordCaptor.capture(), reasonCaptor.capture());
            
            assertThat(recordCaptor.getValue()).isEqualTo(intent);
            assertThat(reasonCaptor.getValue()).contains("execution_error");
            assertThat(reasonCaptor.getValue()).contains("Network timeout");
        }
        
        @Test
        @DisplayName("Should continue processing after individual failure")
        void shouldContinueProcessingAfterIndividualFailure() throws Exception {
            // Given
            IntentRecord failingIntent = createIntentRecord("req-fail", IntentStatus.QUEUED);
            IntentRecord successIntent = createIntentRecord("req-success", IntentStatus.QUEUED);
            
            // Use LinkedHashMap to control order
            Map<String, IntentRecord> intents = new java.util.LinkedHashMap<>();
            intents.put("req-fail", failingIntent);
            intents.put("req-success", successIntent);
            
            when(intentService.getQueuedIntents()).thenReturn(intents);
            when(onChainExecutor.execute(failingIntent))
                .thenThrow(new RuntimeException("Contract reverted"));
            when(onChainExecutor.execute(successIntent))
                .thenReturn(new ExecutionResult(true, "0xsuccess", 200L, "lab", "key", null));
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(onChainExecutor).execute(failingIntent);
            verify(onChainExecutor).execute(successIntent);
            verify(intentService).markFailed(eq(failingIntent), contains("execution_error"));
            verify(intentService).markExecuted(successIntent, "0xsuccess", 200L, "lab", "key");
        }
    }

    // =========================================================================
    // MIXED STATUS TESTS
    // =========================================================================
    
    @Nested
    @DisplayName("Mixed Status Processing")
    class MixedStatusTests {
        
        @Test
        @DisplayName("Should only process QUEUED intents from mixed statuses")
        void shouldOnlyProcessQueuedIntentsFromMixedStatuses() throws Exception {
            // Given
            IntentRecord queuedIntent = createIntentRecord("req-queued", IntentStatus.QUEUED);
            IntentRecord inProgressIntent = createIntentRecord("req-progress", IntentStatus.IN_PROGRESS);
            IntentRecord executedIntent = createIntentRecord("req-executed", IntentStatus.EXECUTED);
            
            Map<String, IntentRecord> intents = new HashMap<>();
            intents.put("req-queued", queuedIntent);
            intents.put("req-progress", inProgressIntent);
            intents.put("req-executed", executedIntent);
            
            when(intentService.getQueuedIntents()).thenReturn(intents);
            when(onChainExecutor.execute(queuedIntent))
                .thenReturn(new ExecutionResult(true, "0xhash", 300L, "lab", "key", null));
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(onChainExecutor, times(1)).execute(any());
            verify(onChainExecutor).execute(queuedIntent);
            verify(intentService).markInProgress(queuedIntent);
            verify(intentService).markExecuted(queuedIntent, "0xhash", 300L, "lab", "key");
        }
        
        @Test
        @DisplayName("Should handle mix of expired and valid intents")
        void shouldHandleMixOfExpiredAndValidIntents() throws Exception {
            // Given
            IntentRecord expiredIntent = createIntentRecord("req-expired", IntentStatus.QUEUED);
            expiredIntent.setExpiresAt(Instant.now().getEpochSecond() - 1000);
            
            IntentRecord validIntent = createIntentRecord("req-valid", IntentStatus.QUEUED);
            validIntent.setExpiresAt(Instant.now().getEpochSecond() + 3600);
            
            Map<String, IntentRecord> intents = new java.util.LinkedHashMap<>();
            intents.put("req-expired", expiredIntent);
            intents.put("req-valid", validIntent);
            
            when(intentService.getQueuedIntents()).thenReturn(intents);
            when(onChainExecutor.execute(validIntent))
                .thenReturn(new ExecutionResult(true, "0xvalid", 400L, "lab", "key", null));
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verify(intentService).markFailed(expiredIntent, "expired");
            verify(onChainExecutor).execute(validIntent);
            verify(intentService).markExecuted(validIntent, "0xvalid", 400L, "lab", "key");
            
            // Verify expired intent was NOT sent to executor
            verify(onChainExecutor, never()).execute(expiredIntent);
        }
    }

    // =========================================================================
    // HELPER METHODS
    // =========================================================================
    
    private IntentRecord createIntentRecord(String requestId, IntentStatus status) {
        IntentRecord record = new IntentRecord(requestId, "LAB_ADD", "test-provider");
        record.setStatus(status);
        record.setExpiresAt(null);
        return record;
    }
}
