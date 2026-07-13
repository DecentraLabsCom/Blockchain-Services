package decentralabs.blockchain.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class SessionObserverAuthenticationFilterTest {
    @Mock private FilterChain filterChain;

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void authenticatesOnlyTheGatewayBoundLeastPrivilegeJwt() throws Exception {
        byte[] secret = "a-32-byte-session-observer-secret!!".getBytes(StandardCharsets.UTF_8);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
        SessionObserverAuthenticationFilter filter = filterWithCredentials("{\"gateway-a\":\"" + encoded + "\"}");
        MockHttpServletRequest request = observationRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token("gateway-a", secret, 60));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("gateway-a");
        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
            .extracting("authority")
            .containsExactly("ROLE_SESSION_OBSERVER");
    }

    @Test
    void authenticatesSessionTicketRedemptionWithTheSameGatewayCredential() throws Exception {
        byte[] secret = "a-32-byte-session-observer-secret!!".getBytes(StandardCharsets.UTF_8);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
        SessionObserverAuthenticationFilter filter = filterWithCredentials("{\"gateway-a\":\"" + encoded + "\"}");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/fmu/session-ticket/redeem");
        request.setRequestURI("/auth/fmu/session-ticket/redeem");
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token("gateway-a", secret, 60));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("gateway-a");
    }

    @Test
    void rejectsExpiredOrUnknownGatewayCredentials() throws Exception {
        byte[] secret = "a-32-byte-session-observer-secret!!".getBytes(StandardCharsets.UTF_8);
        SessionObserverAuthenticationFilter filter = filterWithCredentials("{}");
        MockHttpServletRequest request = observationRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token("gateway-a", secret, -1));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        verify(filterChain, never()).doFilter(request, response);
    }

    private SessionObserverAuthenticationFilter filterWithCredentials(String credentials) {
        SessionObserverAuthenticationFilter filter = new SessionObserverAuthenticationFilter(new ObjectMapper());
        ReflectionTestUtils.setField(filter, "credentialsJson", credentials);
        return filter;
    }

    private MockHttpServletRequest observationRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/access-audit/internal/session-observed");
        request.setRequestURI("/access-audit/internal/session-observed");
        return request;
    }

    private String token(String gatewayId, byte[] secret, long lifetimeSeconds) {
        Instant now = Instant.now();
        SecretKey key = Keys.hmacShaKeyFor(secret);
        return Jwts.builder()
            .issuer(gatewayId)
            .subject(gatewayId)
            .audience().add("session-observation").and()
            .claim("scope", "session-observation:submit")
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plusSeconds(lifetimeSeconds)))
            .signWith(key)
            .compact();
    }
}
