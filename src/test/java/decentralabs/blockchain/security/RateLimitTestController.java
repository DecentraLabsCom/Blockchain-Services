package decentralabs.blockchain.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test controller for rate limit filter tests.
 * Provides stub endpoints that the filter can intercept.
 */
@RestController
class RateLimitTestController {

    @GetMapping("/auth/message")
    public String authMessage() {
        return "ok";
    }

    @PostMapping("/auth/wallet-auth")
    public String walletAuth() {
        return "ok";
    }

    @PostMapping("/auth/wallet-auth2")
    public String walletAuth2() {
        return "ok";
    }

    @PostMapping("/auth/saml-auth")
    public String samlAuth() {
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
