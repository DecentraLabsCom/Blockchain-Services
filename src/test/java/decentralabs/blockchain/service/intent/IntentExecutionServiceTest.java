package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import decentralabs.blockchain.config.ContractEventListenerConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

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

    @Mock
    private IntentRegistrationVerifier registrationVerifier;

    @Mock
    private ObjectProvider<ContractEventListenerConfig> reservationAutoApprovalProcessor;
    
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
            IntentRecord pendingRegistrationIntent = createIntentRecord("req-4", IntentStatus.AUTHORIZED_PENDING_REGISTRATION);
            
            intents.put("req-1", inProgressIntent);
            intents.put("req-2", executedIntent);
            intents.put("req-3", failedIntent);
            intents.put("req-4", pendingRegistrationIntent);
            
            when(intentService.getQueuedIntents()).thenReturn(intents);
            
            // When
            executionService.processQueuedIntents();
            
            // Then
            verifyNoInteractions(onChainExecutor);
            verify(intentService, never()).markInProgress(any());
        }
    }

    @Nested
    @DisplayName("Registration Gate")
    class RegistrationGateTests {

        @Test
        @DisplayName("Should keep authorized reservation pending when registration is not mined yet")
        void shouldKeepAuthorizedIntentPendingWhenRegistrationMissing() {
            IntentRecord intent = createIntentRecord("req-auth-pending", "RESERVATION_REQUEST", IntentStatus.AUTHORIZED_PENDING_REGISTRATION);
            when(intentService.findByRequestId("req-auth-pending")).thenReturn(Optional.of(intent));
            when(registrationVerifier.verifyRegistration(intent))
                .thenReturn(IntentRegistrationVerifier.RegistrationVerificationResult.retryable("intent_not_registered"));

            executionService.processQueuedIntent("req-auth-pending");

            verify(registrationVerifier).verifyRegistration(intent);
            verify(intentService, never()).markQueued(any());
            verifyNoInteractions(onChainExecutor);
        }

        @Test
        @DisplayName("Should execute after on-chain registration verifies")
        void shouldExecuteAfterRegistrationVerifies() throws Exception {
            IntentRecord intent = createIntentRecord("req-auth-ready", "RESERVATION_REQUEST", IntentStatus.AUTHORIZED_PENDING_REGISTRATION);
            when(intentService.findByRequestId("req-auth-ready")).thenReturn(Optional.of(intent));
            when(registrationVerifier.verifyRegistration(intent))
                .thenReturn(IntentRegistrationVerifier.RegistrationVerificationResult.success());
            when(onChainExecutor.execute(intent))
                .thenReturn(new ExecutionResult(true, "0xexec", 777L, "lab", "key", null));

            executionService.processQueuedIntent("req-auth-ready");

            verify(registrationVerifier).verifyRegistration(intent);
            verify(intentService).markQueued(intent);
            verify(onChainExecutor).execute(intent);
            verify(intentService).markExecuted(intent, "0xexec", 777L, "lab", "key");
        }

        @Test
        @DisplayName("Should fail authorized reservation when registered payload mismatches")
        void shouldFailAuthorizedIntentOnRegistrationMismatch() {
            IntentRecord intent = createIntentRecord("req-mismatch", "RESERVATION_REQUEST", IntentStatus.AUTHORIZED_PENDING_REGISTRATION);
            when(intentService.findByRequestId("req-mismatch")).thenReturn(Optional.of(intent));
            when(registrationVerifier.verifyRegistration(intent))
                .thenReturn(IntentRegistrationVerifier.RegistrationVerificationResult.terminalFailure("payload_hash_mismatch"));

            executionService.processQueuedIntent("req-mismatch");

            verify(intentService).markFailed(intent, "payload_hash_mismatch");
            verifyNoInteractions(onChainExecutor);
        }

        @Test
        @DisplayName("Should process pending registrations during scheduled polling")
        void shouldProcessPendingRegistrationsDuringPolling() throws Exception {
            IntentRecord intent = createIntentRecord("req-lost-signal", "RESERVATION_REQUEST", IntentStatus.AUTHORIZED_PENDING_REGISTRATION);
            when(intentService.getQueuedIntents()).thenReturn(Map.of("req-lost-signal", intent));
            when(registrationVerifier.verifyRegistration(intent))
                .thenReturn(IntentRegistrationVerifier.RegistrationVerificationResult.success());
            when(onChainExecutor.execute(intent))
                .thenReturn(new ExecutionResult(true, "0xlost", 778L, "lab", "key", null));

            executionService.processPendingRegistrations();

            verify(intentService).markQueued(intent);
            verify(intentService).markExecuted(intent, "0xlost", 778L, "lab", "key");
        }

        @Test
        @DisplayName("Should fail pending reservation when on-chain intent is already executed")
        void shouldFailWhenOnChainIntentAlreadyExecuted() {
            IntentRecord intent = createIntentRecord("req-executed-onchain", "RESERVATION_REQUEST", IntentStatus.AUTHORIZED_PENDING_REGISTRATION);
            when(intentService.findByRequestId("req-executed-onchain")).thenReturn(Optional.of(intent));
            when(registrationVerifier.verifyRegistration(intent))
                .thenReturn(IntentRegistrationVerifier.RegistrationVerificationResult.terminalFailure("intent_already_executed"));

            executionService.processQueuedIntent("req-executed-onchain");

            verify(intentService).markFailed(intent, "intent_already_executed");
            verifyNoInteractions(onChainExecutor);
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
        @DisplayName("Should process a queued intent immediately by request id")
        void shouldProcessQueuedIntentImmediatelyByRequestId() throws Exception {
            // Given
            IntentRecord intent = createIntentRecord("req-immediate", IntentStatus.QUEUED);
            when(intentService.findByRequestId("req-immediate")).thenReturn(Optional.of(intent));
            when(onChainExecutor.execute(intent))
                .thenReturn(new ExecutionResult(true, "0ximmediate", 101L, "lab", "key", null));

            // When
            executionService.processQueuedIntent("req-immediate");

            // Then
            verify(intentService).markInProgress(intent);
            verify(onChainExecutor).execute(intent);
            verify(intentService).markExecuted(intent, "0ximmediate", 101L, "lab", "key");
            verify(intentService, never()).getQueuedIntents();
        }

        @Test
        @DisplayName("Should trigger reservation auto-approval after reservation request execution")
        void shouldTriggerAutoApprovalAfterReservationRequestExecution() throws Exception {
            // Given
            IntentRecord intent = createIntentRecord("req-reservation", "RESERVATION_REQUEST", IntentStatus.QUEUED);
            intent.setReservationKey("0x" + "12".repeat(32));
            when(intentService.findByRequestId("req-reservation")).thenReturn(Optional.of(intent));
            when(onChainExecutor.execute(intent))
                .thenReturn(new ExecutionResult(true, "0xreservation", 102L, null, "0x" + "34".repeat(32), null));
            ContractEventListenerConfig processor = mock(ContractEventListenerConfig.class);
            doAnswer(invocation -> {
                java.util.function.Consumer<ContractEventListenerConfig> consumer = invocation.getArgument(0);
                consumer.accept(processor);
                return null;
            }).when(reservationAutoApprovalProcessor).ifAvailable(any());

            // When
            executionService.processQueuedIntent("req-reservation");

            // Then
            verify(processor).processReservationRequestFromChain("0x" + "34".repeat(32));
        }

        @Test
        @DisplayName("Should not auto-approve direct bookings after execution")
        void shouldNotAutoApproveDirectBookingsAfterExecution() throws Exception {
            // Given
            IntentRecord intent = createIntentRecord("req-direct", "DIRECT_BOOKING", IntentStatus.QUEUED);
            intent.setReservationKey("0x" + "56".repeat(32));
            when(intentService.findByRequestId("req-direct")).thenReturn(Optional.of(intent));
            when(onChainExecutor.execute(intent))
                .thenReturn(new ExecutionResult(true, "0xdirect", 103L, null, "0x" + "56".repeat(32), null));

            // When
            executionService.processQueuedIntent("req-direct");

            // Then
            verify(reservationAutoApprovalProcessor, never()).ifAvailable(any());
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
        @DisplayName("Should not execute when another replica owns the database claim")
        void shouldSkipIntentClaimedByAnotherReplica() {
            IntentRecord intent = createIntentRecord("req-claimed", IntentStatus.QUEUED);
            when(intentService.getQueuedIntents()).thenReturn(Map.of("req-claimed", intent));
            doThrow(new IntentClaimRejectedException("req-claimed"))
                .when(intentService).markInProgress(intent);

            executionService.processQueuedIntents();

            verifyNoInteractions(onChainExecutor);
            verify(intentService, never()).markFailed(any(), any());
        }

        @Test
        @DisplayName("Should keep broadcast transaction submitted when receipt is temporarily unavailable")
        void shouldMarkReceiptTimeoutAsSubmitted() throws Exception {
            IntentRecord intent = createIntentRecord("req-submitted", IntentStatus.QUEUED);
            when(intentService.getQueuedIntents()).thenReturn(Map.of("req-submitted", intent));
            when(onChainExecutor.execute(intent)).thenReturn(
                new ExecutionResult(false, "0xbroadcast", null, null, null, "receipt_error: timeout")
            );

            executionService.processQueuedIntents();

            verify(intentService).markSubmitted(intent, "0xbroadcast", "receipt_error: timeout");
            verify(intentService, never()).markFailed(any(), any());
        }

        @Test
        @DisplayName("Should retry an uncertain broadcast with its reserved nonce")
        void shouldRetryUncertainBroadcastWithoutFailingIntent() throws Exception {
            IntentRecord intent = createIntentRecord("req-uncertain", IntentStatus.QUEUED);
            intent.setTransactionNonce(java.math.BigInteger.valueOf(44));
            when(intentService.getQueuedIntents()).thenReturn(Map.of("req-uncertain", intent));
            when(onChainExecutor.execute(intent)).thenReturn(
                new ExecutionResult(false, null, null, null, null, "dispatch_uncertain")
            );

            executionService.processQueuedIntents();

            verify(intentService).markRetryable(intent, "dispatch_uncertain");
            verify(intentService, never()).markFailed(any(), any());
        }

        @Test
        @DisplayName("Should reconcile a submitted transaction after its receipt is mined")
        void shouldReconcileSubmittedReceipt() throws Exception {
            IntentRecord intent = createIntentRecord("req-mined-later", IntentStatus.SUBMITTED);
            intent.setTxHash("0xbroadcast");
            when(intentService.getQueuedIntents()).thenReturn(Map.of("req-mined-later", intent));
            when(onChainExecutor.inspectReceipt(intent)).thenReturn(
                new IntentOnChainExecutor.ReceiptResult(
                    IntentOnChainExecutor.ReceiptState.MINED_SUCCESS,
                    123L,
                    "77",
                    null
                )
            );

            executionService.monitorSubmittedIntents();

            verify(intentService).markExecuted(intent, "0xbroadcast", 123L, "77", null);
            verify(intentService, never()).markFailed(any(), any());
        }
        
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
        return createIntentRecord(requestId, "LAB_ADD", status);
    }

    private IntentRecord createIntentRecord(String requestId, String action, IntentStatus status) {
        IntentRecord record = new IntentRecord(requestId, action, "test-provider");
        record.setStatus(status);
        record.setExpiresAt(null);
        return record;
    }
}
