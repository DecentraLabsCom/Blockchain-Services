package decentralabs.blockchain.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

class AccessTokenAuthenticationFilterTest {

    private TestableAccessTokenAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new TestableAccessTokenAuthenticationFilter();
        ReflectionTestUtils.setField(filter, "accessToken", "expected-token");
        ReflectionTestUtils.setField(filter, "accessTokenHeader", "X-Access-Token");
        ReflectionTestUtils.setField(filter, "accessTokenCookie", "access_token");
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldNotFilter_nonTreasuryPath() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/auth/message");

        assertThat(filter.shouldSkip(request)).isTrue();
    }

    @Test
    void shouldFilter_treasuryAdminPath() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/treasury/admin/payouts");

        assertThat(filter.shouldSkip(request)).isFalse();
    }

    @Test
    void blankConfiguredToken_passesThroughWithoutAuthentication() throws Exception {
        ReflectionTestUtils.setField(filter, "accessToken", " ");
        MockHttpServletRequest request = treasuryAdminRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.runFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void validQueryToken_setsInternalAuthentication() throws Exception {
        MockHttpServletRequest request = treasuryAdminRequest();
        request.setParameter("token", "expected-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.runFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication.getName()).isEqualTo("internal");
        assertThat(authentication.getAuthorities())
            .extracting(Object::toString)
            .containsExactly("ROLE_INTERNAL");
    }

    @Test
    void validHeaderToken_setsInternalAuthentication() throws Exception {
        MockHttpServletRequest request = treasuryAdminRequest();
        request.addHeader("X-Access-Token", "expected-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.runFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void validCookieToken_setsInternalAuthentication() throws Exception {
        MockHttpServletRequest request = treasuryAdminRequest();
        request.setCookies(new Cookie("access_token", "expected-token"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.runFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void invalidToken_returnsUnauthorizedAndStopsChain() throws Exception {
        MockHttpServletRequest request = treasuryAdminRequest();
        request.setParameter("token", "wrong-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.runFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_UNAUTHORIZED);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void existingAuthentication_isPreserved() throws Exception {
        Authentication existing = new UsernamePasswordAuthenticationToken(
            "already-authenticated",
            null,
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        SecurityContextHolder.getContext().setAuthentication(existing);

        MockHttpServletRequest request = treasuryAdminRequest();
        request.addHeader("X-Access-Token", "expected-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.runFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(existing);
    }

    @Test
    void missingProvidedToken_onProtectedPathLeavesContextEmpty() throws Exception {
        MockHttpServletRequest request = treasuryAdminRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.runFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    private MockHttpServletRequest treasuryAdminRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/treasury/admin/payouts");
        return request;
    }

    private static final class TestableAccessTokenAuthenticationFilter extends AccessTokenAuthenticationFilter {
        boolean shouldSkip(MockHttpServletRequest request) {
            return super.shouldNotFilter(request);
        }

        void runFilter(
            MockHttpServletRequest request,
            MockHttpServletResponse response,
            FilterChain filterChain
        ) throws ServletException, IOException {
            super.doFilterInternal(request, response, filterChain);
        }
    }
}
