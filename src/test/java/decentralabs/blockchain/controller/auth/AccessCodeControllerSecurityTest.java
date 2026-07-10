package decentralabs.blockchain.controller.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.AccessCodeRedeemRequest;
import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.service.auth.AccessCodeService;
import decentralabs.blockchain.service.auth.InstitutionalCheckInService;
import decentralabs.blockchain.service.auth.SamlAuthService;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class AccessCodeControllerSecurityTest {

    @Test
    void rejectsRedeemRequestsWithoutTheGatewayRedeemerSecret() {
        AccessCodeService accessCodeService = mock(AccessCodeService.class);
        SamlAuthController controller = new SamlAuthController(
            mock(SamlAuthService.class),
            mock(InstitutionalCheckInService.class),
            accessCodeService
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
            accessCodeService
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
