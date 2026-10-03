package decentralabs.blockchain.controller.accesspolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import decentralabs.blockchain.service.accesspolicy.LabCategoryAccessPolicyService;
import decentralabs.blockchain.service.auth.InstitutionalSessionCredentialService;
import decentralabs.blockchain.service.auth.MarketplaceEndpointAuthService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

class AccessPolicyControllerTest {

    @Test
    void rejectsMissingEvaluationRequestWithBadRequest() {
        AccessPolicyController controller = new AccessPolicyController(
            mock(MarketplaceEndpointAuthService.class),
            mock(InstitutionalSessionCredentialService.class),
            mock(LabCategoryAccessPolicyService.class)
        );

        ResponseStatusException exception = assertThrows(
            ResponseStatusException.class,
            () -> controller.evaluate("Bearer service-token", null)
        );

        assertEquals(HttpStatus.BAD_REQUEST.value(), exception.getStatusCode().value());
    }
}
