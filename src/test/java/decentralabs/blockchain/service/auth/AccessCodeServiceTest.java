package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AccessCodeResponse;
import decentralabs.blockchain.dto.auth.AuthResponse;
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
        AccessCodeService service = new AccessCodeService(provider);

        AccessCodeResponse issued = service.issue("signed-jwt", "https://lab.example/guacamole/");
        assertThat(issued.getAccessCode()).isNotBlank().doesNotContain("signed-jwt");

        AuthResponse redeemed = service.redeem(issued.getAccessCode());
        assertThat(redeemed.getToken()).isEqualTo("signed-jwt");
        assertThatThrownBy(() -> service.redeem(issued.getAccessCode()))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Invalid or expired access code");
    }
}
