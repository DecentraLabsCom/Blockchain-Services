package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
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
        Instant issuedAt = Instant.parse("2026-08-18T13:00:00Z");
        Instant expiresAt = Instant.parse("2026-08-18T14:00:00Z");

        when(samlValidationService.validateSamlAssertionWithSignature("signed-saml"))
            .thenReturn(attributes);
        when(samlValidationService.resolveStableUserId(attributes, "principal", null))
            .thenReturn("user@institution.edu");
        when(credentialService.issue(
                eq("institution.edu"),
                eq("user@institution.edu"),
                eq("principal"),
                any(String.class)
            ))
            .thenReturn(new InstitutionalSessionCredentialService.IssuedCredential(
                "backend-session-token",
                "user@institution.edu",
                "institution.edu",
                "0x" + "a".repeat(64),
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
            any(String.class)
        );
    }

    @Test
    void create_requiresMarketplaceIdentityClaimsWhenAuthorizationIsEnabled() throws Exception {
        InstitutionalSessionRequest request = new InstitutionalSessionRequest();
        request.setSamlAssertion("signed-saml");
        request.setStableUserIdMode("principal");
        when(samlValidationService.validateSamlAssertionWithSignature("signed-saml"))
            .thenReturn(Map.of(
                "puc", "user@institution.edu",
                "affiliation", "institution.edu"
            ));

        assertThatThrownBy(() -> service.create(request, Map.of(), true))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("institutional_identity_mismatch");
    }
}
