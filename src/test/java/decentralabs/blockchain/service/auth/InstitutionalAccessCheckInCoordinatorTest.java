package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.util.PucHashUtil;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class InstitutionalAccessCheckInCoordinatorTest {
    @Mock
    private InstitutionalCheckInOutboxService outboxService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private InstitutionalCheckInDirectoryService directoryService;

    @Mock
    private RemoteInstitutionalCheckInClient remoteCheckInClient;

    @Mock
    private InstitutionalWalletNonceDispatcher nonceDispatcher;

    private InstitutionalAccessCheckInCoordinator coordinator;

    @BeforeEach
    void setUp() {
        coordinator = new InstitutionalAccessCheckInCoordinator(
            outboxService,
            institutionalWalletService,
            directoryService,
            remoteCheckInClient,
            nonceDispatcher
        );
        ReflectionTestUtils.setField(coordinator, "delegationEnabled", true);
    }

    @Test
    void enqueuesAndBroadcastsImmediatelyWhenLocalSignerIsAuthorized() throws Exception {
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x9999999999999999999999999999999999999999");
        when(directoryService.isAuthorizedCheckInSigner(
            "0x1111111111111111111111111111111111111111",
            "0x9999999999999999999999999999999999999999"
        )).thenReturn(true);
        InstitutionalCheckInOutboxRecord pending = record("PENDING");
        when(outboxService.enqueueAccessGranted(any(), any(), any(), any(), any(), any())).thenReturn(pending);
        InstitutionalCheckInOutboxClaim claim = claim(pending);
        when(outboxService.claim(pending.id())).thenReturn(claim);

        coordinator.recordAccessGranted(
            request(),
            claims(),
            Map.of(
                "reservationKey", "0xabc",
                "lab", BigInteger.valueOf(42),
                "reservationStatus", BigInteger.ONE,
                "guacSessionId", "session-1"
            )
        );

        verify(outboxService).enqueueAccessGranted(
            "0xabc",
            "42",
            "0x1111111111111111111111111111111111111111",
            "0x9999999999999999999999999999999999999999",
            PucHashUtil.hashPuc("puc-123"),
            "session-1"
        );
        verify(outboxService).claim(pending.id());
        verify(nonceDispatcher).dispatch(claim, false);
        verify(remoteCheckInClient, never()).submit(any(), any());
    }

    @Test
    void doesNotRebroadcastAnExistingActiveTransaction() throws Exception {
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x9999999999999999999999999999999999999999");
        when(directoryService.isAuthorizedCheckInSigner(any(), any())).thenReturn(true);
        InstitutionalCheckInOutboxRecord submitted = record("SUBMITTED");
        when(outboxService.enqueueAccessGranted(any(), any(), any(), any(), any(), any())).thenReturn(submitted);
        when(outboxService.claim(submitted.id())).thenReturn(null);

        coordinator.recordAccessGranted(
            request(),
            claims(),
            Map.of("reservationKey", "0xabc", "lab", BigInteger.valueOf(42), "reservationStatus", BigInteger.ONE)
        );

        verify(nonceDispatcher, never()).dispatch(any());
    }

    @Test
    void explicitlyRestartsAndBroadcastsOnlyATerminalCheckInAfterRevalidation() throws Exception {
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x9999999999999999999999999999999999999999");
        when(directoryService.isAuthorizedCheckInSigner(
            "0x1111111111111111111111111111111111111111",
            "0x9999999999999999999999999999999999999999"
        )).thenReturn(true);
        InstitutionalCheckInOutboxRecord failed = record("MINED_FAILED");
        InstitutionalCheckInOutboxRecord restarted = record("PENDING");
        when(outboxService.enqueueAccessGranted(any(), any(), any(), any(), any(), any())).thenReturn(failed);
        when(outboxService.restartTerminalFailure(failed.id())).thenReturn(restarted);
        InstitutionalCheckInOutboxClaim claim = claim(restarted);
        when(outboxService.claim(restarted.id())).thenReturn(claim);

        coordinator.recordAccessGranted(
            request(),
            claims(),
            Map.of("reservationKey", "0xabc", "lab", BigInteger.valueOf(42), "reservationStatus", BigInteger.ONE)
        );

        verify(outboxService).restartTerminalFailure(7L);
        verify(nonceDispatcher).dispatch(claim, false);
    }

    @Test
    void preservesReplacementIntentWhenTheCombinedFlowClaimsImmediately() throws Exception {
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x9999999999999999999999999999999999999999");
        when(directoryService.isAuthorizedCheckInSigner(any(), any())).thenReturn(true);
        InstitutionalCheckInOutboxRecord replacement = record("REPLACEMENT_PENDING");
        when(outboxService.enqueueAccessGranted(any(), any(), any(), any(), any(), any())).thenReturn(replacement);
        InstitutionalCheckInOutboxClaim claim = claim(replacement);
        when(outboxService.claim(replacement.id())).thenReturn(claim);

        coordinator.recordAccessGranted(
            request(),
            claims(),
            Map.of("reservationKey", "0xabc", "lab", BigInteger.valueOf(42), "reservationStatus", BigInteger.ONE)
        );

        verify(nonceDispatcher).dispatch(claim, true);
        verify(nonceDispatcher, never()).dispatch(claim);
    }

    @Test
    void preservesAnUncertainImmediateBroadcastForBackgroundReconciliation() throws Exception {
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x9999999999999999999999999999999999999999");
        when(directoryService.isAuthorizedCheckInSigner(any(), any())).thenReturn(true);
        InstitutionalCheckInOutboxRecord pending = record("PENDING");
        when(outboxService.enqueueAccessGranted(any(), any(), any(), any(), any(), any())).thenReturn(pending);
        InstitutionalCheckInOutboxClaim claim = claim(pending);
        when(outboxService.claim(pending.id())).thenReturn(claim);
        when(nonceDispatcher.dispatch(claim, false))
            .thenThrow(new InstitutionalWalletDispatchException("uncertain", new IllegalStateException("rpc response lost")));

        coordinator.recordAccessGranted(
            request(),
            claims(),
            Map.of("reservationKey", "0xabc", "lab", BigInteger.valueOf(42), "reservationStatus", BigInteger.ONE)
        );

        verify(outboxService).markBroadcastUncertain(
            eq(claim),
            eq(pending.attempts() + 1),
            eq("Initial institutional check-in broadcast outcome is uncertain")
        );
    }

    @Test
    void retriesImmediateDispatchOnlyWhenFailureHappenedBeforeBroadcast() throws Exception {
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x9999999999999999999999999999999999999999");
        when(directoryService.isAuthorizedCheckInSigner(any(), any())).thenReturn(true);
        InstitutionalCheckInOutboxRecord pending = record("PENDING");
        when(outboxService.enqueueAccessGranted(any(), any(), any(), any(), any(), any())).thenReturn(pending);
        InstitutionalCheckInOutboxClaim claim = claim(pending);
        when(outboxService.claim(pending.id())).thenReturn(claim);
        when(nonceDispatcher.dispatch(claim, false)).thenThrow(new InstitutionalWalletDispatchException(
            "blocked", InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED,
            new IllegalStateException("allocator blocked")
        ));
        when(outboxService.markRetry(any(InstitutionalCheckInOutboxClaim.class), any(Integer.class), any(), any())).thenReturn(true);

        coordinator.recordAccessGranted(
            request(),
            claims(),
            Map.of("reservationKey", "0xabc", "lab", BigInteger.valueOf(42), "reservationStatus", BigInteger.ONE)
        );

        verify(outboxService).markRetry(
            eq(claim), eq(pending.attempts()), any(Instant.class),
            eq("Initial institutional check-in transaction was not broadcast; retrying")
        );
        verify(outboxService, never()).markBroadcastUncertain(any(InstitutionalCheckInOutboxClaim.class), any(Integer.class), any());
    }

    @Test
    void skipsCheckInWhenReservationAccessAlreadyAuthorized() {
        coordinator.recordAccessGranted(
            request(),
            claims(),
            Map.of(
                "reservationKey", "0xabc",
                "lab", BigInteger.valueOf(42),
                "reservationStatus", BigInteger.valueOf(2)
            )
        );

        verify(outboxService, never()).enqueueAccessGranted(any(), any(), any(), any(), any(), any());
        verify(remoteCheckInClient, never()).submit(any(), any());
    }

    @Test
    void delegatesSynchronouslyWhenLocalSignerIsNotAuthorized() {
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x9999999999999999999999999999999999999999");
        when(directoryService.isAuthorizedCheckInSigner(
            "0x1111111111111111111111111111111111111111",
            "0x9999999999999999999999999999999999999999"
        )).thenReturn(false);
        when(directoryService.resolveOrganizationBackendUrl("org.example"))
            .thenReturn("https://consumer.example");
        CheckInResponse response = new CheckInResponse();
        response.setValid(true);
        when(remoteCheckInClient.submit(eq("https://consumer.example"), any(InstitutionalCheckInRequest.class)))
            .thenReturn(response);

        coordinator.recordAccessGranted(
            request(),
            claims(),
            Map.of(
                "reservationKey", "0xabc",
                "lab", BigInteger.valueOf(42),
                "reservationStatus", BigInteger.ONE
            )
        );

        ArgumentCaptor<InstitutionalCheckInRequest> captor = ArgumentCaptor.forClass(InstitutionalCheckInRequest.class);
        verify(remoteCheckInClient).submit(eq("https://consumer.example"), captor.capture());
        verify(outboxService, never()).enqueueAccessGranted(any(), any(), any(), any(), any(), any());
        InstitutionalCheckInRequest delegated = captor.getValue();
        org.assertj.core.api.Assertions.assertThat(delegated.getReservationKey()).isEqualTo("0xabc");
        org.assertj.core.api.Assertions.assertThat(delegated.getLabId()).isEqualTo("42");
        org.assertj.core.api.Assertions.assertThat(delegated.getPuc()).isEqualTo("puc-123");
    }

    @Test
    void rejectsAccessWhenPucClaimIsMissingForPendingCheckIn() {
        assertThatThrownBy(() -> coordinator.recordAccessGranted(
            request(),
            Map.of(
                "affiliation", "org.example",
                "payerInstitutionWallet", "0x1111111111111111111111111111111111111111"
            ),
            Map.of(
                "reservationKey", "0xabc",
                "lab", BigInteger.valueOf(42),
                "reservationStatus", BigInteger.ONE
            )
        ))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Missing PUC");
    }

    private SamlAuthRequest request() {
        SamlAuthRequest request = new SamlAuthRequest();
        request.setMarketplaceToken("market-token");
        request.setSamlAssertion("saml");
        request.setReservationKey("0xabc");
        return request;
    }

    private Map<String, Object> claims() {
        return Map.of(
            "affiliation", "org.example",
            "payerInstitutionWallet", "0x1111111111111111111111111111111111111111",
            "puc", "puc-123"
        );
    }

    private InstitutionalCheckInOutboxRecord record(String status) {
        String txHash = "PENDING".equals(status) ? null : "0xtx";
        return new InstitutionalCheckInOutboxRecord(
            7L, "0xabc", "42", "0xwallet", "0xpuc", "session", status, 1, Instant.now(),
            txHash, "0xwallet", BigInteger.ONE, Instant.now()
        );
    }

    private InstitutionalCheckInOutboxClaim claim(InstitutionalCheckInOutboxRecord record) {
        return new InstitutionalCheckInOutboxClaim(record, "claim-id", "worker", record.version());
    }
}
