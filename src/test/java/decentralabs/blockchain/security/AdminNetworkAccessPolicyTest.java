package decentralabs.blockchain.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

class AdminNetworkAccessPolicyTest {

    private AdminNetworkAccessPolicy policy;

    @BeforeEach
    void setUp() {
        policy = new AdminNetworkAccessPolicy();
        ReflectionTestUtils.setField(policy, "adminDashboardLocalOnly", true);
        ReflectionTestUtils.setField(policy, "adminDashboardAllowPrivate", false);
        ReflectionTestUtils.setField(policy, "allowPrivateNetworks", false);
        ReflectionTestUtils.setField(policy, "accessTokenRequired", true);
        ReflectionTestUtils.setField(policy, "configuredCidrs", "");
    }

    @Test
    void allowsLoopbackWithoutToken() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");

        assertThat(policy.isRequestAllowed(request, () -> false)).isTrue();
    }

    @Test
    void blocksPrivateNetworkWhenPrivateAccessDisabled() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.20.1.5");

        assertThat(policy.isRequestAllowed(request, () -> true)).isFalse();
    }

    @Test
    void allowsAnyPrivateRangeWhenEnabledAndNoCidrsConfigured() {
        ReflectionTestUtils.setField(policy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(policy, "allowPrivateNetworks", true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.20.1.5");

        assertThat(policy.isRequestAllowed(request, () -> true)).isTrue();
    }

    @Test
    void blocksPrivateAddressOutsideConfiguredCidrs() {
        ReflectionTestUtils.setField(policy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(policy, "allowPrivateNetworks", true);
        ReflectionTestUtils.setField(policy, "configuredCidrs", "10.20.0.0/16");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.30.1.5");

        assertThat(policy.isRequestAllowed(request, () -> true)).isFalse();
    }

    @Test
    void allowsPrivateAddressInsideConfiguredCidrs() {
        ReflectionTestUtils.setField(policy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(policy, "allowPrivateNetworks", true);
        ReflectionTestUtils.setField(policy, "configuredCidrs", "10.20.0.0/16,192.168.50.0/24");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.20.1.5");

        assertThat(policy.isRequestAllowed(request, () -> true)).isTrue();
    }

    @Test
    void trustsForwardedClientOnlyFromPrivateProxy() {
        ReflectionTestUtils.setField(policy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(policy, "allowPrivateNetworks", true);
        ReflectionTestUtils.setField(policy, "configuredCidrs", "10.20.0.0/16");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("172.17.0.10");
        request.addHeader("X-Forwarded-For", "10.20.1.9");

        assertThat(policy.isRequestAllowed(request, () -> true)).isTrue();
    }

    @Test
    void ignoresSpoofedForwardedHeaderFromPublicRemote() {
        ReflectionTestUtils.setField(policy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(policy, "allowPrivateNetworks", true);
        ReflectionTestUtils.setField(policy, "configuredCidrs", "10.20.0.0/16");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.20");
        request.addHeader("X-Forwarded-For", "10.20.1.9");

        assertThat(policy.isRequestAllowed(request, () -> true)).isFalse();
    }

    @Test
    void skipsTokenCheckWhenNotRequired() {
        ReflectionTestUtils.setField(policy, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(policy, "allowPrivateNetworks", true);
        ReflectionTestUtils.setField(policy, "accessTokenRequired", false);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.20.1.5");
        AtomicBoolean invoked = new AtomicBoolean(false);

        assertThat(policy.isRequestAllowed(request, () -> {
            invoked.set(true);
            return false;
        })).isTrue();
        assertThat(invoked.get()).isFalse();
    }
}
