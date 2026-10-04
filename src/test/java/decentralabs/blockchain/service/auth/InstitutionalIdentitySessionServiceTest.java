package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.IdentitySessionRequest;
import decentralabs.blockchain.dto.auth.InstitutionalSessionResponse;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class InstitutionalIdentitySessionServiceTest {

    private static final String HASH = "0x" + "a".repeat(64);
    private static final String VERSION = "oidc-id-token-keccak-v1";

    @Test
    void createsAProviderNeutralSessionFromSignedMarketplaceClaims() {
        InstitutionalSessionCredentialService credentialService = mock(InstitutionalSessionCredentialService.class);
        ExternalOidcTokenValidationService tokenValidationService = mock(ExternalOidcTokenValidationService.class);
        InstitutionalIdentitySessionService service = new InstitutionalIdentitySessionService(credentialService, tokenValidationService);
        Instant issuedAt = Instant.parse("2026-10-04T10:00:00Z");
        Instant expiresAt = issuedAt.plusSeconds(3600);
        when(credentialService.issueIdentity(
            eq("uned.es"),
            eq("oidc:entra-id:tenant-1:oid-123"),
            eq("oidc-issuer-subject-v1"),
            eq("oidc"),
            eq("entra-id"),
            eq("https://login.microsoftonline.com/tenant-1/v2.0"),
            eq("oid-123"),
            eq(HASH),
            eq(VERSION)
        )).thenReturn(new InstitutionalSessionCredentialService.IssuedCredential(
            "institutional-session-token",
            "oidc:entra-id:tenant-1:oid-123",
            "uned.es",
            HASH,
            VERSION,
            issuedAt,
            expiresAt,
            "oidc",
            "entra-id",
            "https://login.microsoftonline.com/tenant-1/v2.0",
            "oid-123",
            HASH,
            VERSION
        ));

        IdentitySessionRequest request = new IdentitySessionRequest();
        request.setStableUserIdMode("oidc-issuer-subject-v1");
        request.setExternalIdToken("external-id-token");
        when(tokenValidationService.validate(
            "entra-id",
            "external-id-token",
            "https://login.microsoftonline.com/tenant-1/v2.0",
            "oid-123",
            HASH,
            "nonce-1"
        )).thenReturn(new ExternalOidcTokenValidationService.ValidatedToken(
            "https://login.microsoftonline.com/tenant-1/v2.0",
            "oid-123",
            "tenant-1",
            Map.of()
        ));

        InstitutionalSessionResponse response = service.create(request, claims(), true);

        assertThat(response.getSessionToken()).isEqualTo("institutional-session-token");
        assertThat(response.getIdentityProtocol()).isEqualTo("oidc");
        assertThat(response.getIdentityProvider()).isEqualTo("entra-id");
        assertThat(response.getIdentityEvidenceHash()).isEqualTo(HASH);
        assertThat(response.getIdentityEvidenceHashVersion()).isEqualTo(VERSION);
        verify(credentialService).issueIdentity(
            "uned.es",
            "oidc:entra-id:tenant-1:oid-123",
            "oidc-issuer-subject-v1",
            "oidc",
            "entra-id",
            "https://login.microsoftonline.com/tenant-1/v2.0",
            "oid-123",
            HASH,
            VERSION
        );
    }

    @Test
    void rejectsIdentitySessionWithoutEvidenceHash() {
        InstitutionalSessionCredentialService credentialService = mock(InstitutionalSessionCredentialService.class);
        InstitutionalIdentitySessionService service = new InstitutionalIdentitySessionService(credentialService);
        Map<String, Object> claims = new HashMap<>(claims());
        claims.remove("identityEvidenceHash");

        assertThatThrownBy(() -> service.create(new IdentitySessionRequest(), claims, true))
            .hasMessageContaining("missing_identity_evidence_hash");
    }

    @Test
    void rejectsAnOidcSessionWithAnUnexpectedEvidenceHashVersion() {
        InstitutionalSessionCredentialService credentialService = mock(InstitutionalSessionCredentialService.class);
        InstitutionalIdentitySessionService service = new InstitutionalIdentitySessionService(credentialService);
        Map<String, Object> claims = new HashMap<>(claims());
        claims.put("identityEvidenceHashVersion", "vc-canonical-keccak-v1");

        assertThatThrownBy(() -> service.create(new IdentitySessionRequest(), claims, true))
            .hasMessageContaining("unsupported_identity_evidence_hash_version");
    }

    private Map<String, Object> claims() {
        return Map.of(
            "identityProtocol", "oidc",
            "identityProvider", "entra-id",
            "identityIssuer", "https://login.microsoftonline.com/tenant-1/v2.0",
            "identitySubject", "oid-123",
            "identityEvidenceHash", HASH,
            "identityEvidenceHashVersion", VERSION,
            "identityNonce", "nonce-1",
            "stableUserId", "oidc:entra-id:tenant-1:oid-123",
            "puc", "oidc:entra-id:tenant-1:oid-123",
            "affiliation", "uned.es"
        );
    }
}
