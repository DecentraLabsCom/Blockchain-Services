package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AccessCodeResponse;
import decentralabs.blockchain.dto.auth.AuthResponse;
import java.util.Map;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AccessCodeServiceTest {
    @Test
    @SuppressWarnings("unchecked")
    void accessCodeIsOpaqueAndSingleUse() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        JwtService jwtService = mock(JwtService.class);
        when(jwtService.extractAllClaims("signed-jwt")).thenReturn(labClaims());
        AccessCodeService service = new AccessCodeService(provider, jwtService);

        AccessCodeResponse issued = service.issue("signed-jwt");
        assertThat(issued.getAccessCode()).isNotBlank().doesNotContain("signed-jwt");
        assertThat(issued.getLabURL()).isEqualTo("https://lab.example/guacamole/");
        assertThat(issued.getResourceType()).isEqualTo("lab");

        AuthResponse redeemed = service.redeem(issued.getAccessCode(), "lab.example");
        assertThat(redeemed.getToken()).isEqualTo("signed-jwt");
        assertThat(redeemed.getResourceType()).isEqualTo("lab");
        assertThatThrownBy(() -> service.redeem(issued.getAccessCode(), "lab.example"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Invalid or expired access code");
    }

    @Test
    @SuppressWarnings("unchecked")
    void persistentModeNeverFallsBackToTheInstanceLocalCache() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        JwtService jwtService = mock(JwtService.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jwtService.extractAllClaims("signed-jwt")).thenReturn(labClaims());
        when(jdbcTemplate.query(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(org.springframework.jdbc.core.PreparedStatementSetter.class), org.mockito.ArgumentMatchers.any(org.springframework.jdbc.core.ResultSetExtractor.class)))
            .thenReturn(null);
        AccessCodeService service = new AccessCodeService(
            provider,
            jwtService,
            new AccessCodeTokenCipher(Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]))
        );

        AccessCodeResponse issued = service.issue("signed-jwt");

        assertThatThrownBy(() -> service.redeem(issued.getAccessCode(), "lab.example"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Invalid or expired access code");
    }

    @Test
    @SuppressWarnings("unchecked")
    void issuesOpaqueCodesForFmuCredentials() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        JwtService jwtService = mock(JwtService.class);
        when(jwtService.extractAllClaims("fmu-jwt")).thenReturn(Map.of(
            "resourceType", "fmu",
            "labURL", "https://lab.example/fmu/model",
            "aud", "https://lab.example/fmu/model",
            "targetGatewayId", "lab.example"
        ));
        AccessCodeService service = new AccessCodeService(provider, jwtService);

        AccessCodeResponse issued = service.issue("fmu-jwt");

        assertThat(issued.getAccessCode()).isNotBlank().doesNotContain("fmu-jwt");
        assertThat(issued.getLabURL()).isEqualTo("https://lab.example/fmu/model");
        assertThat(issued.getResourceType()).isEqualTo("fmu");
        assertThat(service.redeem(issued.getAccessCode(), "lab.example").getToken()).isEqualTo("fmu-jwt");
    }

    @Test
    @SuppressWarnings("unchecked")
    void accessCodeExpiryNeverExceedsCredentialExpiry() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        AccessCodeService service = new AccessCodeService(provider, mock(JwtService.class));
        ReflectionTestUtils.setField(service, "ttlSeconds", 300L);

        assertThat(service.boundedCodeExpiry(1_000L, 1_030L)).isEqualTo(1_030L);
        assertThat(service.boundedCodeExpiry(1_000L, 2_000L)).isEqualTo(1_300L);
    }

    @Test
    @SuppressWarnings("unchecked")
    void recoversTheSameUnconsumedDeliveryAfterTheProviderResponseIsLost() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        JwtService jwtService = mock(JwtService.class);
        when(jwtService.extractAllClaims("signed-jwt")).thenReturn(labClaims());
        AccessCodeService service = new AccessCodeService(provider, jwtService);

        AccessCodeResponse issued = service.issue("signed-jwt", "0xreservation", 3L);
        AccessCodeResponse recovered = service.recoverDelivery("0xreservation", 3L);

        assertThat(recovered.getAccessCode()).isEqualTo(issued.getAccessCode());
        assertThat(service.redeem(recovered.getAccessCode(), "lab.example").getToken()).isEqualTo("signed-jwt");
        assertThat(service.recoverDelivery("0xreservation", 3L)).isNull();
    }

    private Map<String, Object> labClaims() {
        return Map.of(
            "resourceType", "lab",
            "labURL", "https://lab.example/guacamole/",
            "aud", "https://lab.example/guacamole/",
            "targetGatewayId", "lab.example"
        );
    }

    @Test
    @SuppressWarnings("unchecked")
    void wrongGatewayCannotConsumeTheCode() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        JwtService jwtService = mock(JwtService.class);
        when(jwtService.extractAllClaims("signed-jwt")).thenReturn(labClaims());
        AccessCodeService service = new AccessCodeService(
            provider,
            jwtService,
            new AccessCodeTokenCipher(Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]))
        );
        AccessCodeResponse issued = service.issue("signed-jwt");

        assertThatThrownBy(() -> service.redeem(issued.getAccessCode(), "other.example"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("not valid for this gateway");
        assertThat(service.redeem(issued.getAccessCode(), "lab.example").getToken())
            .isEqualTo("signed-jwt");
    }
}
