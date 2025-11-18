package decentralabs.blockchain.controller.organization;

import decentralabs.blockchain.dto.organization.InstitutionInviteTokenRequest;
import decentralabs.blockchain.dto.organization.InstitutionInviteTokenResponse;
import decentralabs.blockchain.service.organization.InstitutionInviteService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/onboarding/token")
@RequiredArgsConstructor
@ConditionalOnProperty(value = "features.organizations.enabled", havingValue = "true", matchIfMissing = true)
public class InstitutionInviteController {

    private final InstitutionInviteService inviteService;

    @PostMapping("/apply")
    public InstitutionInviteTokenResponse apply(@Valid @RequestBody InstitutionInviteTokenRequest request) {
        return inviteService.applyInvite(request);
    }
}
