package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AccessCodeResponse;
import decentralabs.blockchain.dto.auth.AuthResponse;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;

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

        AuthResponse redeemed = service.redeem(issued.getAccessCode());
        assertThat(redeemed.getToken()).isEqualTo("signed-jwt");
        assertThatThrownBy(() -> service.redeem(issued.getAccessCode()))
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
        AccessCodeService service = new AccessCodeService(provider, jwtService);

        AccessCodeResponse issued = service.issue("signed-jwt");

        assertThatThrownBy(() -> service.redeem(issued.getAccessCode()))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Invalid or expired access code");
    }

    @Test
    @SuppressWarnings("unchecked")
    void rejectsNonGuacamoleCredentialsBeforeIssuingACode() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        JwtService jwtService = mock(JwtService.class);
        when(jwtService.extractAllClaims("fmu-jwt")).thenReturn(Map.of(
            "resourceType", "fmu",
            "labURL", "https://lab.example/fmu/model",
            "aud", "https://lab.example/fmu/model"
        ));
        AccessCodeService service = new AccessCodeService(provider, jwtService);

        assertThatThrownBy(() -> service.issue("fmu-jwt"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Guacamole");
    }

    private Map<String, Object> labClaims() {
        return Map.of(
            "resourceType", "lab",
            "labURL", "https://lab.example/guacamole/",
            "aud", "https://lab.example/guacamole/"
        );
    }
}
