package decentralabs.blockchain.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("GatewayUrlResolver Tests")
class GatewayUrlResolverTest {

    @Nested
    @DisplayName("Base Domain Resolution Tests")
    class BaseDomainResolutionTests {

        @Test
        @DisplayName("Should prefer configured base domain")
        void shouldPreferConfiguredBaseDomain() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "https://custom.example",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://custom.example");
        }

        @Test
        @DisplayName("Should strip trailing slash from configured domain")
        void shouldStripTrailingSlash() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "https://custom.example/",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://custom.example");
        }

        @Test
        @DisplayName("Should strip multiple trailing slashes")
        void shouldStripMultipleTrailingSlashes() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "https://custom.example///",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://custom.example");
        }

        @Test
        @DisplayName("Should trim whitespace from configured domain")
        void shouldTrimWhitespace() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "  https://custom.example  ",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://custom.example");
        }

        @Test
        @DisplayName("Should build from server name and HTTPS port")
        void shouldBuildFromServerNameAndHttpsPort() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "gateway.example",
                "9443",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://gateway.example:9443");
        }

        @Test
        @DisplayName("Should omit port 443 for HTTPS")
        void shouldOmitPort443ForHttps() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "secure.example",
                "443",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://secure.example");
        }

        @Test
        @DisplayName("Should use HTTP when only HTTP port is set")
        void shouldUseHttpWhenOnlyHttpPortIsSet() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "api.example",
                "",
                "9080",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("http://api.example:9080");
        }

        @Test
        @DisplayName("Should omit port 80 for HTTP")
        void shouldOmitPort80ForHttp() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "api.example",
                "",
                "80",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("http://api.example");
        }

        @Test
        @DisplayName("Should fallback to localhost and application port when unset")
        void shouldFallbackToLocalhostAndApplicationPortWhenUnset() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("http://localhost:8080");
        }

        @Test
        @DisplayName("Should use custom application port")
        void shouldUseCustomApplicationPort() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "",
                "",
                "",
                "3000"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("http://localhost:3000");
        }

        @Test
        @DisplayName("Should prioritize HTTPS over HTTP when both ports set")
        void shouldPrioritizeHttpsOverHttp() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "dual.example",
                "443",
                "80",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://dual.example");
        }
    }

    @Nested
    @DisplayName("Issuer URL Resolution Tests")
    class IssuerUrlResolutionTests {

        @Test
        @DisplayName("Should append auth path to base domain")
        void shouldAppendAuthPathToBaseDomain() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "https://custom.example",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveIssuer("/auth")).isEqualTo("https://custom.example/auth");
        }

        @Test
        @DisplayName("Should handle auth path without leading slash")
        void shouldHandleAuthPathWithoutLeadingSlash() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "https://custom.example",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveIssuer("auth")).isEqualTo("https://custom.example/auth");
        }

        @Test
        @DisplayName("Should use default /auth path when null")
        void shouldUseDefaultPathWhenNull() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "https://custom.example",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveIssuer(null)).isEqualTo("https://custom.example/auth");
        }

        @Test
        @DisplayName("Should use default /auth path when blank")
        void shouldUseDefaultPathWhenBlank() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "https://custom.example",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveIssuer("   ")).isEqualTo("https://custom.example/auth");
        }

        @Test
        @DisplayName("Should handle custom auth path")
        void shouldHandleCustomAuthPath() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "https://custom.example",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveIssuer("/oauth2/token")).isEqualTo("https://custom.example/oauth2/token");
        }

        @Test
        @DisplayName("Should combine server name HTTPS with issuer path")
        void shouldCombineServerNameHttpsWithIssuerPath() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "gateway.example",
                "9443",
                "",
                "8080"
            );

            assertThat(resolver.resolveIssuer("/auth")).isEqualTo("https://gateway.example:9443/auth");
        }

        @Test
        @DisplayName("Should combine localhost fallback with issuer path")
        void shouldCombineLocalhostFallbackWithIssuerPath() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "",
                "",
                "",
                "8080"
            );

            assertThat(resolver.resolveIssuer("/auth")).isEqualTo("http://localhost:8080/auth");
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle empty strings for all parameters")
        void shouldHandleEmptyStringsForAllParameters() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "",
                "",
                "",
                ""
            );

            // Should default to http://localhost:80 but omit port
            String result = resolver.resolveBaseDomain();
            assertThat(result).startsWith("http://localhost");
        }

        @Test
        @DisplayName("Should handle null-like empty configured domain")
        void shouldHandleNullLikeEmptyConfiguredDomain() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "   ",
                "server.example",
                "443",
                "",
                "8080"
            );

            // Should fall back to server name since base domain is effectively empty
            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://server.example");
        }

        @Test
        @DisplayName("Should trim server name")
        void shouldTrimServerName() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "  gateway.example  ",
                "443",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://gateway.example");
        }

        @Test
        @DisplayName("Should trim HTTPS port")
        void shouldTrimHttpsPort() {
            GatewayUrlResolver resolver = new GatewayUrlResolver(
                "",
                "gateway.example",
                "  9443  ",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://gateway.example:9443");
        }
    }
}

