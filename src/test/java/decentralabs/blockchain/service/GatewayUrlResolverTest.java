package decentralabs.blockchain.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class GatewayUrlResolverTest {

    @Test
    void shouldPreferConfiguredBaseDomain() {
        GatewayUrlResolver resolver = new GatewayUrlResolver(
            "https://custom.example",
            "",
            "",
            "",
            "8080"
        );

        assertThat(resolver.resolveBaseDomain()).isEqualTo("https://custom.example");
        assertThat(resolver.resolveIssuer("/auth")).isEqualTo("https://custom.example/auth");
    }

    @Test
    void shouldBuildFromServerNameAndHttpsPort() {
        GatewayUrlResolver resolver = new GatewayUrlResolver(
            "",
            "gateway.example",
            "9443",
            "",
            "8080"
        );

        assertThat(resolver.resolveBaseDomain()).isEqualTo("https://gateway.example:9443");
        assertThat(resolver.resolveIssuer("/auth")).isEqualTo("https://gateway.example:9443/auth");
    }

    @Test
    void shouldFallbackToLocalhostAndApplicationPortWhenUnset() {
        GatewayUrlResolver resolver = new GatewayUrlResolver(
            "",
            "",
            "",
            "",
            "8080"
        );

        assertThat(resolver.resolveBaseDomain()).isEqualTo("http://localhost:8080");
        assertThat(resolver.resolveIssuer("/auth")).isEqualTo("http://localhost:8080/auth");
    }
}

