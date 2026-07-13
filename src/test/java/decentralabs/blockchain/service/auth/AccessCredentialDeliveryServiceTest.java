package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.AccessCodeResponse;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AccessCredentialDeliveryServiceTest {
    @Mock private AccessCodeService accessCodeService;
    @Mock private AccessCredentialAuditService auditService;

    @Test
    void persistsAccessCodeAndAuditInsideOneDeliveryBoundary() {
        AccessCredentialDeliveryService service = new AccessCredentialDeliveryService(accessCodeService, auditService);
        var issuedToken = new JwtService.IssuedToken("jwt", "jti", 100L, 200L);
        var lease = new AccessAuthorizationProvisioningService.ProvisioningLease("0xreservation", "fence", 3L);
        var request = new SamlAuthRequest();
        Map<String, Object> claims = Map.of("puc", "user");
        Map<String, Object> booking = Map.of("resourceType", "lab");
        when(accessCodeService.issue("jwt", "0xreservation", 3L))
            .thenReturn(new AccessCodeResponse("opaque", "https://gateway.example/guacamole", "lab"));

        var response = service.deliver(issuedToken, request, claims, booking, lease);

        assertThat(response.getAccessCode()).isEqualTo("opaque");
        assertThat(response.getReservationKey()).isEqualTo("0xreservation");
        InOrder order = inOrder(accessCodeService, auditService);
        order.verify(accessCodeService).issue("jwt", "0xreservation", 3L);
        order.verify(auditService).recordJwtIssuedRequired(request, claims, booking, issuedToken);
    }

    @Test
    void doesNotReturnDeliveryWhenDurableAuditFails() {
        AccessCredentialDeliveryService service = new AccessCredentialDeliveryService(accessCodeService, auditService);
        var issuedToken = new JwtService.IssuedToken("jwt", "jti", 100L, 200L);
        var lease = new AccessAuthorizationProvisioningService.ProvisioningLease("0xreservation", "fence", 3L);
        var request = new SamlAuthRequest();
        Map<String, Object> claims = Map.of("puc", "user");
        Map<String, Object> booking = Map.of("resourceType", "lab");
        when(accessCodeService.issue("jwt", "0xreservation", 3L))
            .thenReturn(new AccessCodeResponse("opaque", "https://gateway.example/guacamole", "lab"));
        org.mockito.Mockito.doThrow(new IllegalStateException("audit unavailable"))
            .when(auditService).recordJwtIssuedRequired(request, claims, booking, issuedToken);

        assertThatThrownBy(() -> service.deliver(issuedToken, request, claims, booking, lease))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("audit unavailable");
        verify(accessCodeService).issue("jwt", "0xreservation", 3L);
        verifyNoMoreInteractions(accessCodeService);
    }
}
