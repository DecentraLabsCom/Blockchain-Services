package decentralabs.blockchain.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("BackendUrlResolver Tests")
class BackendUrlResolverTest {

    @Nested
    @DisplayName("Base Domain Resolution Tests")
    class BaseDomainResolutionTests {

        @Test
        @DisplayName("Should prefer configured base domain")
        void shouldPreferConfiguredBaseDomain() {
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
                "",
                "backend.example",
                "9443",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://backend.example:9443");
        }

        @Test
        @DisplayName("Should omit port 443 for HTTPS")
        void shouldOmitPort443ForHttps() {
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
                "",
                "backend.example",
                "9443",
                "",
                "8080"
            );

            assertThat(resolver.resolveIssuer("/auth")).isEqualTo("https://backend.example:9443/auth");
        }

        @Test
        @DisplayName("Should combine localhost fallback with issuer path")
        void shouldCombineLocalhostFallbackWithIssuerPath() {
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
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
            BackendUrlResolver resolver = new BackendUrlResolver(
                "",
                "  backend.example  ",
                "443",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://backend.example");
        }

        @Test
        @DisplayName("Should trim HTTPS port")
        void shouldTrimHttpsPort() {
            BackendUrlResolver resolver = new BackendUrlResolver(
                "",
                "backend.example",
                "  9443  ",
                "",
                "8080"
            );

            assertThat(resolver.resolveBaseDomain()).isEqualTo("https://backend.example:9443");
        }
    }
}

