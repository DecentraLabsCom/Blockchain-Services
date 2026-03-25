package decentralabs.blockchain.security;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test controller for rate limit filter tests.
 * Provides stub endpoints that the filter can intercept.
 */
@RestController
class RateLimitTestController {

    @PostMapping("/auth/saml-auth")
    public String samlAuth() {
        return "ok";
    }

    @PostMapping("/auth/checkin-institutional")
    public String institutionalCheckin() {
        return "ok";
    }

    @GetMapping("/auth/jwks")
    public String jwks() {
        return "{\"keys\":[]}";
    }

    @GetMapping("/.well-known/openid-configuration")
    public String openidConfig() {
        return "{\"issuer\":\"test\"}";
    }

    @GetMapping("/health")
    public String health() {
        return "ok";
    }
}
