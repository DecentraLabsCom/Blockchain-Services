package decentralabs.blockchain.service.accesspolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.health.LabMetadata;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.service.auth.InstitutionalSessionCredentialService.Credential;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.intent.IntentRecord;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class LabCategoryAccessPolicyServiceTest {
    @Mock AccessPolicyPersistenceService policies;
    @Mock InstitutionalIdentityContextPersistenceService identities;
    @Mock LabMetadataService metadata;
    private LabCategoryAccessPolicyService service;
    private Credential credential;

    @BeforeEach
    void setUp() {
        service = new LabCategoryAccessPolicyService(policies, identities, metadata);
        credential = new Credential("user", "uni.example", "principal", "0x" + "a".repeat(64), "saml-attestation-v1",
            Instant.now(), Instant.now().plusSeconds(600), Instant.now().plusSeconds(600), "jti");
    }

    @Test
    void noActivePolicyAllowsPaidLabWithoutFetchingMetadataOrIdentity() {
        when(policies.find("uni.example")).thenReturn(null);

        var result = service.evaluate(credential, BigInteger.ONE, BigInteger.TEN, List.of());

        assertEquals("ALLOW_NO_POLICY", result.reasonCode());
        verify(metadata, never()).getLabMetadataForLab(BigInteger.ONE);
    }

    @Test
    void activePolicyUsesAuthoritativeMetadataAndStoredContext() {
        var profile = new AccessPolicyProfile("uni.example", "Policy", 2, true, AccessPolicyDecision.DENY,
            List.of(new AccessPolicyGroup("staff", "Staff", Map.of("role", List.of("staff")), List.of("Chemistry"), List.of())), List.of());
        when(policies.find("uni.example")).thenReturn(profile);
        when(metadata.getLabMetadataForLab(BigInteger.ONE)).thenReturn(LabMetadata.builder().category("Chemistry").build());
        when(identities.find("uni.example", decentralabs.blockchain.util.PucHashUtil.hashPuc("user")))
            .thenReturn(new InstitutionalIdentityContext("uni.example", "ref", "saml", "idp", Map.of("role", List.of("student")), Instant.now(), null));

        var result = service.evaluate(credential, BigInteger.ONE, BigInteger.TEN, List.of("Other"));

        assertEquals("NO_MATCH_USER_DISCIPLINE", result.reasonCode());
        assertThrows(ResponseStatusException.class, () -> service.enforce(credential, BigInteger.ONE, BigInteger.TEN, List.of()));
    }

    @Test
    void activePolicyFailsClosedWhenIdentityContextCannotBeResolved() {
        when(policies.find("uni.example")).thenReturn(new AccessPolicyProfile("uni.example", "Policy", 1, true,
            AccessPolicyDecision.ALLOW, List.of(), List.of()));
        when(metadata.getLabMetadataForLab(BigInteger.ONE)).thenReturn(LabMetadata.builder().category("Chemistry").build());
        when(identities.find("uni.example", decentralabs.blockchain.util.PucHashUtil.hashPuc("user"))).thenReturn(null);

        var result = service.evaluate(credential, BigInteger.ONE, BigInteger.TEN, List.of());

        assertEquals("IDENTITY_CONTEXT_UNAVAILABLE", result.reasonCode());
        assertEquals(false, result.allowed());
    }

    @Test
    void storedReservationRecheckUsesPersistedHashImmediatelyBeforeExecution() {
        String pucHash = decentralabs.blockchain.util.PucHashUtil.hashPuc("user");
        var profile = new AccessPolicyProfile("uni.example", "Policy", 3, true, AccessPolicyDecision.DENY,
            List.of(new AccessPolicyGroup("staff", "Staff", Map.of("role", List.of("staff")), List.of("Chemistry"), List.of())), List.of());
        when(policies.find("uni.example")).thenReturn(profile);
        when(metadata.getLabMetadataForLab(BigInteger.ONE)).thenReturn(LabMetadata.builder().category("Chemistry").build());
        when(identities.find("uni.example", pucHash)).thenReturn(new InstitutionalIdentityContext(
            "uni.example", pucHash, "saml", "idp", Map.of("role", List.of("staff")), Instant.now(), null));

        IntentRecord record = new IntentRecord("request", "RESERVATION_REQUEST", "provider");
        record.setInstitutionId("uni.example");
        record.setPucHash(pucHash);
        record.setLabId("1");
        ReservationIntentPayload payload = new ReservationIntentPayload();
        payload.setLabId(BigInteger.ONE);
        payload.setPrice(BigInteger.TEN);
        record.setReservationPayload(payload);

        service.enforceStored(record);

        verify(identities).find("uni.example", pucHash);
    }

    @Test
    void storedReservationRecheckDeniesWhenContextDisappears() {
        when(policies.find("uni.example")).thenReturn(new AccessPolicyProfile("uni.example", "Policy", 4, true,
            AccessPolicyDecision.ALLOW, List.of(), List.of()));
        when(metadata.getLabMetadataForLab(BigInteger.ONE)).thenReturn(LabMetadata.builder().category("Chemistry").build());
        when(identities.find("uni.example", "0x" + "a".repeat(64))).thenReturn(null);

        IntentRecord record = new IntentRecord("request", "RESERVATION_REQUEST", "provider");
        record.setInstitutionId("uni.example");
        record.setPucHash("0x" + "a".repeat(64));
        record.setLabId("1");
        ReservationIntentPayload payload = new ReservationIntentPayload();
        payload.setLabId(BigInteger.ONE);
        payload.setPrice(BigInteger.TEN);
        record.setReservationPayload(payload);

        assertThrows(ResponseStatusException.class, () -> service.enforceStored(record));
    }
}
