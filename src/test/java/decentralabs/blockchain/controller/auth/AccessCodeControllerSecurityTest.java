package decentralabs.blockchain.controller.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.AccessCodeRedeemRequest;
import decentralabs.blockchain.dto.auth.AccessCodeIssueRequest;
import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.service.auth.AccessCodeService;
import decentralabs.blockchain.service.auth.InstitutionalCheckInService;
import decentralabs.blockchain.service.auth.MarketplaceEndpointAuthService;
import decentralabs.blockchain.service.auth.SamlAuthService;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class AccessCodeControllerSecurityTest {

    @Test
    void rejectsIssueRequestsWithoutMarketplaceAuthentication() {
        AccessCodeService accessCodeService = mock(AccessCodeService.class);
        SamlAuthController controller = new SamlAuthController(
            mock(SamlAuthService.class),
            mock(InstitutionalCheckInService.class),
            accessCodeService,
            mock(MarketplaceEndpointAuthService.class)
        );
        AccessCodeIssueRequest request = new AccessCodeIssueRequest();
        request.setToken("issued-access-jwt");

        var response = controller.issueAccessCode(null, request);

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        verifyNoInteractions(accessCodeService);
    }

    @Test
    void issuesOnlyWhenMarketplaceAuthenticatesTheServerToServerCall() {
        AccessCodeService accessCodeService = mock(AccessCodeService.class);
        MarketplaceEndpointAuthService marketplaceAuth = mock(MarketplaceEndpointAuthService.class);
        SamlAuthController controller = new SamlAuthController(
            mock(SamlAuthService.class),
            mock(InstitutionalCheckInService.class),
            accessCodeService,
            marketplaceAuth
        );
        AccessCodeIssueRequest request = new AccessCodeIssueRequest();
        request.setToken("issued-access-jwt");
        ReflectionTestUtils.setField(controller, "marketplaceEndpointAuthenticationEnabled", true);
        when(marketplaceAuth.enforceToken("marketplace-jwt", null)).thenReturn(java.util.Map.of());
        when(accessCodeService.issue("issued-access-jwt")).thenReturn(mock(decentralabs.blockchain.dto.auth.AccessCodeResponse.class));

        var response = controller.issueAccessCode("Bearer marketplace-jwt", request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        verify(marketplaceAuth).enforceToken("marketplace-jwt", null);
        verify(accessCodeService).issue("issued-access-jwt");
    }

    @Test
    void rejectsRedeemRequestsWithoutTheGatewayRedeemerSecret() {
        AccessCodeService accessCodeService = mock(AccessCodeService.class);
        SamlAuthController controller = new SamlAuthController(
            mock(SamlAuthService.class),
            mock(InstitutionalCheckInService.class),
            accessCodeService,
            mock(MarketplaceEndpointAuthService.class)
        );
        ReflectionTestUtils.setField(controller, "accessCodeRedeemerToken", "redeemer-secret");
        AccessCodeRedeemRequest request = new AccessCodeRedeemRequest();
        request.setAccessCode("opaque-code");

        var response = controller.redeemAccessCode(null, request);

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        verifyNoInteractions(accessCodeService);
    }

    @Test
    void redeemsOnlyWhenTheGatewaySuppliesTheConfiguredSecret() {
        AccessCodeService accessCodeService = mock(AccessCodeService.class);
        SamlAuthController controller = new SamlAuthController(
            mock(SamlAuthService.class),
            mock(InstitutionalCheckInService.class),
            accessCodeService,
            mock(MarketplaceEndpointAuthService.class)
        );
        ReflectionTestUtils.setField(controller, "accessCodeRedeemerToken", "redeemer-secret");
        AccessCodeRedeemRequest request = new AccessCodeRedeemRequest();
        request.setAccessCode("opaque-code");
        when(accessCodeService.redeem("opaque-code")).thenReturn(new AuthResponse("jwt", "https://lab.example/guacamole/"));

        var response = controller.redeemAccessCode("redeemer-secret", request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        verify(accessCodeService).redeem("opaque-code");
    }
}
