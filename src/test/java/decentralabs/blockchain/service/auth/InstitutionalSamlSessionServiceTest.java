package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.InstitutionalSessionRequest;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class InstitutionalSamlSessionServiceTest {

    @Mock
    private SamlValidationService samlValidationService;

    @Mock
    private InstitutionalSessionCredentialService credentialService;

    private InstitutionalSamlSessionService service;

    @BeforeEach
    void setUp() {
        service = new InstitutionalSamlSessionService(samlValidationService, credentialService);
    }

    @Test
    void create_usesValidatedSamlIdentityWhenMarketplaceAuthorizationIsDisabled() throws Exception {
        InstitutionalSessionRequest request = new InstitutionalSessionRequest();
        request.setSamlAssertion("signed-saml");
        request.setStableUserIdMode("principal");
        Map<String, String> attributes = Map.of(
            "puc", "user@institution.edu|targeted",
            "eduPersonPrincipalName", "user@institution.edu",
            "affiliation", "Institution.EDU"
        );
        SamlAssertionAttributes validated = new SamlAssertionAttributes(
            "https://idp.example",
            "user@institution.edu|targeted",
            "Institution.EDU",
            null,
            null,
            java.util.List.of(),
            Map.of(),
            "0x" + "a".repeat(64),
            SamlAttestationHashService.HASH_VERSION
        );
        Instant issuedAt = Instant.parse("2026-08-18T13:00:00Z");
        Instant expiresAt = Instant.parse("2026-08-18T14:00:00Z");

        when(samlValidationService.validateSamlAssertionDetailed("signed-saml"))
            .thenReturn(validated);
        when(samlValidationService.toIdentityAttributeMap(validated)).thenReturn(attributes);
        when(samlValidationService.resolveStableUserId(attributes, "principal", null))
            .thenReturn("user@institution.edu");
        when(credentialService.issue(
                eq("institution.edu"),
                eq("user@institution.edu"),
                eq("principal"),
                eq("0x" + "a".repeat(64)),
                eq(SamlAttestationHashService.HASH_VERSION)
            ))
            .thenReturn(new InstitutionalSessionCredentialService.IssuedCredential(
                "backend-session-token",
                "user@institution.edu",
                "institution.edu",
                "0x" + "a".repeat(64),
                SamlAttestationHashService.HASH_VERSION,
                issuedAt,
                expiresAt
            ));

        var response = service.create(request, Map.of(), false);

        assertThat(response.getSessionToken()).isEqualTo("backend-session-token");
        assertThat(response.getExpiresAt()).isEqualTo(expiresAt);
        verify(credentialService).issue(
            eq("institution.edu"),
            eq("user@institution.edu"),
            eq("principal"),
            eq("0x" + "a".repeat(64)),
            eq(SamlAttestationHashService.HASH_VERSION)
        );
    }

    @Test
    void create_requiresMarketplaceIdentityClaimsWhenAuthorizationIsEnabled() throws Exception {
        InstitutionalSessionRequest request = new InstitutionalSessionRequest();
        request.setSamlAssertion("signed-saml");
        request.setStableUserIdMode("principal");
        SamlAssertionAttributes validated = new SamlAssertionAttributes(
            "https://idp.example",
            "user@institution.edu",
            "institution.edu",
            null,
            null,
            java.util.List.of(),
            Map.of(),
            "0x" + "a".repeat(64),
            SamlAttestationHashService.HASH_VERSION
        );
        when(samlValidationService.validateSamlAssertionDetailed("signed-saml"))
            .thenReturn(validated);
        when(samlValidationService.toIdentityAttributeMap(validated)).thenReturn(Map.of(
                "puc", "user@institution.edu",
                "affiliation", "institution.edu"
            ));

        assertThatThrownBy(() -> service.create(request, Map.of(), true))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("institutional_identity_mismatch");
    }
}
