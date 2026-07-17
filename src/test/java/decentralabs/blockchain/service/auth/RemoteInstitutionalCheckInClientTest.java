package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInStatusRequest;
import decentralabs.blockchain.service.BackendUrlResolver;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class RemoteInstitutionalCheckInClientTest {
    @Mock private RemoteInstitutionalCheckInClient.HostResolver hostResolver;
    @Mock private RemoteInstitutionalCheckInClient.PinnedTransport transport;
    @Mock private BackendUrlResolver backendUrlResolver;

    private RemoteInstitutionalCheckInClient client;
    private InetAddress publicAddress;
    private HttpServer httpServer;

    @AfterEach
    void tearDown() {
        if (httpServer != null) {
            httpServer.stop(0);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        publicAddress = InetAddress.getByAddress("institution.example", new byte[] {93, (byte) 184, (byte) 216, 34});
        client = new RemoteInstitutionalCheckInClient(new ObjectMapper(), hostResolver, transport);
        ReflectionTestUtils.setField(client, "endpointPath", "/auth/checkin-institutional");
        lenient().when(hostResolver.resolve("institution.example")).thenReturn(List.of(publicAddress));
    }

    @Test
    void submitPinsValidatedDnsAndCallsAuthEndpointWhenRegisteredUrlEndsWithApi() throws Exception {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        CheckInResponse expected = new CheckInResponse();
        expected.setValid(true);
        URI endpoint = URI.create("https://institution.example/auth/checkin-institutional");
        when(transport.post(endpoint, request, List.of(publicAddress)))
            .thenReturn(RemoteInstitutionalCheckInClient.RemoteCheckInResult.success(expected));

        CheckInResponse response = client.submit("https://institution.example/api", request);

        assertThat(response).isSameAs(expected);
        verify(transport).post(endpoint, request, List.of(publicAddress));
    }

    @Test
    void submitPreservesNonApiBasePath() throws Exception {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        CheckInResponse expected = new CheckInResponse();
        URI endpoint = URI.create("https://institution.example/gateway/auth/checkin-institutional");
        when(transport.post(endpoint, request, List.of(publicAddress)))
            .thenReturn(RemoteInstitutionalCheckInClient.RemoteCheckInResult.success(expected));

        assertThat(client.submit("https://institution.example/gateway", request)).isSameAs(expected);
    }

    @Test
    void rejectsPrivateAndMixedDnsAnswersBeforeConnecting() throws Exception {
        InetAddress privateAddress = InetAddress.getByAddress("institution.example", new byte[] {10, 0, 0, 8});
        when(hostResolver.resolve("institution.example")).thenReturn(List.of(publicAddress, privateAddress));

        assertThatThrownBy(() -> client.submit("https://institution.example", new InstitutionalCheckInRequest()))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("non-public");
    }

    @Test
    void rejectsLoopbackLiteralAndHttpByDefault() throws Exception {
        InetAddress loopback = InetAddress.getByAddress("127.0.0.1", new byte[] {127, 0, 0, 1});
        when(hostResolver.resolve("127.0.0.1")).thenReturn(List.of(loopback));
        assertThatThrownBy(() -> client.submit("https://127.0.0.1", new InstitutionalCheckInRequest()))
            .isInstanceOf(SecurityException.class);
        assertThatThrownBy(() -> client.submit("http://institution.example", new InstitutionalCheckInRequest()))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("HTTPS");
    }

    @Test
    void rejectsCredentialsQueryAndFragment() {
        for (String url : List.of(
            "https://user@institution.example",
            "https://institution.example?target=internal",
            "https://institution.example#fragment"
        )) {
            assertThatThrownBy(() -> client.submit(url, new InstitutionalCheckInRequest()))
                .as(url)
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void acceptsPublicIpv6WithoutMisclassifyingTheIetfSpecialPurposeRange() throws Exception {
        InetAddress publicIpv6 = InetAddress.getByName("2001:4860:4860::8888");
        when(hostResolver.resolve("institution.example")).thenReturn(List.of(publicIpv6));
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        CheckInResponse expected = new CheckInResponse();
        URI endpoint = URI.create("https://institution.example/auth/checkin-institutional");
        when(transport.post(endpoint, request, List.of(publicIpv6)))
            .thenReturn(RemoteInstitutionalCheckInClient.RemoteCheckInResult.success(expected));

        assertThat(client.submit("https://institution.example", request)).isSameAs(expected);
    }

    @Test
    void submitDetailedPreservesNon2xxBodyAndRetryAfter() throws Exception {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        CheckInResponse body = new CheckInResponse();
        body.setReason("CHECKIN_MANUAL_INTERVENTION");
        body.setRetryable(false);
        URI endpoint = URI.create("https://institution.example/auth/checkin-institutional");
        when(transport.post(endpoint, request, List.of(publicAddress)))
            .thenReturn(new RemoteInstitutionalCheckInClient.RemoteCheckInResult(409, body, "7"));

        RemoteInstitutionalCheckInClient.RemoteCheckInResult result =
            client.submitDetailed("https://institution.example", request);

        assertThat(result.status()).isEqualTo(409);
        assertThat(result.body()).isSameAs(body);
        assertThat(result.retryAfter()).isEqualTo("7");
    }

    @Test
    void infersRetryabilityFromTransientStatusOnlyWhenBodyDoesNotSpecifyIt() {
        CheckInResponse explicitFalse = new CheckInResponse();
        explicitFalse.setRetryable(false);

        assertThat(new RemoteInstitutionalCheckInClient.RemoteCheckInResult(503, explicitFalse, "9")
            .isRetryable()).isFalse();
        assertThat(new RemoteInstitutionalCheckInClient.RemoteCheckInResult(429, null, "9")
            .isRetryable()).isTrue();
        assertThat(new RemoteInstitutionalCheckInClient.RemoteCheckInResult(500, null, "9")
            .isRetryable()).isFalse();
    }

    @Test
    void preservesStatusAndRetryAfterWhenRemoteProxyReturnsNonJsonError() throws Exception {
        httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] responseBody = "<html>upstream unavailable</html>".getBytes(StandardCharsets.UTF_8);
        httpServer.createContext("/auth/checkin-institutional", exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.getResponseHeaders().set("Retry-After", "17");
            exchange.sendResponseHeaders(502, responseBody.length);
            try (var output = exchange.getResponseBody()) {
                output.write(responseBody);
            }
        });
        httpServer.start();

        RemoteInstitutionalCheckInClient realClient = new RemoteInstitutionalCheckInClient(new ObjectMapper());
        ReflectionTestUtils.setField(realClient, "allowHttp", true);
        ReflectionTestUtils.setField(realClient, "allowPrivateNetworks", true);

        RemoteInstitutionalCheckInClient.RemoteCheckInResult result = realClient.submitDetailed(
            "http://127.0.0.1:" + httpServer.getAddress().getPort(),
            new InstitutionalCheckInRequest()
        );

        assertThat(result.status()).isEqualTo(502);
        assertThat(result.body()).isNull();
        assertThat(result.retryAfter()).isEqualTo("17");
        assertThat(result.isRetryable()).isTrue();
    }

    @Test
    void queriesDelegatedCheckInStatusThroughTheAuthenticatedStatusEndpoint() throws Exception {
        InstitutionalCheckInStatusRequest request = new InstitutionalCheckInStatusRequest();
        request.setMarketplaceToken("market-token");
        request.setReservationKey("0xabc");
        request.setLabId("42");
        CheckInResponse body = new CheckInResponse();
        body.setReason("CHECKIN_MANUAL_INTERVENTION");
        body.setRetryable(false);
        URI endpoint = URI.create("https://institution.example/auth/checkin-institutional/status");
        when(transport.post(endpoint, request, List.of(publicAddress)))
            .thenReturn(new RemoteInstitutionalCheckInClient.RemoteCheckInResult(409, body, null));

        RemoteInstitutionalCheckInClient.RemoteCheckInResult result = client.queryStatus(
            "https://institution.example", request
        );

        assertThat(result.status()).isEqualTo(409);
        assertThat(result.body()).isSameAs(body);
    }

    @Test
    void rejectsDelegationToThisBackendBeforeDnsResolution() throws Exception {
        when(backendUrlResolver.resolveBaseDomain()).thenReturn("https://institution.example/");
        RemoteInstitutionalCheckInClient selfAwareClient = new RemoteInstitutionalCheckInClient(
            new ObjectMapper(), backendUrlResolver, hostResolver, transport
        );
        ReflectionTestUtils.setField(selfAwareClient, "endpointPath", "/auth/checkin-institutional");

        RemoteInstitutionalCheckInClient.RemoteCheckInResult result = selfAwareClient.submitDetailed(
            "https://institution.example/api", new InstitutionalCheckInRequest()
        );

        assertThat(result.status()).isEqualTo(409);
        assertThat(result.body().getReason()).isEqualTo("CHECKIN_SIGNER_NOT_AUTHORIZED");
        assertThat(result.body().getRetryable()).isFalse();
        verify(hostResolver, org.mockito.Mockito.never()).resolve("institution.example");
        verify(transport, org.mockito.Mockito.never()).post(org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void rejectsSelfDelegationWhenRegisteredUrlAddsApiToAPathPrefixedBase() throws Exception {
        RemoteInstitutionalCheckInClient selfAwareClient = new RemoteInstitutionalCheckInClient(
            new ObjectMapper(), backendUrlResolver, hostResolver, transport
        );
        ReflectionTestUtils.setField(selfAwareClient, "endpointPath", "/auth/checkin-institutional");
        ReflectionTestUtils.setField(selfAwareClient, "configuredPublicBaseUrl", "https://institution.example/gateway");

        RemoteInstitutionalCheckInClient.RemoteCheckInResult result = selfAwareClient.submitDetailed(
            "https://institution.example/gateway/api", new InstitutionalCheckInRequest()
        );

        assertThat(result.status()).isEqualTo(409);
        assertThat(result.body().getReason()).isEqualTo("CHECKIN_SIGNER_NOT_AUTHORIZED");
        assertThat(result.body().getRetryable()).isFalse();
        verify(hostResolver, org.mockito.Mockito.never()).resolve("institution.example");
        verify(transport, org.mockito.Mockito.never()).post(org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void rejectsASecondDelegationHopBeforeResolvingTheRemoteBackend() throws Exception {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        request.setDelegationHop(1);
        request.setDelegationTrace(List.of("https://backend-a.example/auth/checkin-institutional"));

        RemoteInstitutionalCheckInClient.RemoteCheckInResult result = client.submitDetailed(
            "https://backend-b.example", request
        );

        assertThat(result.status()).isEqualTo(409);
        assertThat(result.body().getReason()).isEqualTo("CHECKIN_DELEGATION_LOOP");
        verify(hostResolver, org.mockito.Mockito.never()).resolve("backend-b.example");
        verify(transport, org.mockito.Mockito.never()).post(org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void doesNotWrapAnInvalidMaximumDelegationHopWhenPreparingMetadata() {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        request.setDelegationHop(Integer.MAX_VALUE);

        ReflectionTestUtils.invokeMethod(client, "prepareDelegationMetadata", request);

        assertThat(request.getDelegationHop()).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void rejectsADelegationTraceContainingTheTargetBaseBeforeResolvingDns() throws Exception {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        request.setDelegationTrace(List.of("https://backend-b.example"));

        RemoteInstitutionalCheckInClient.RemoteCheckInResult result = client.submitDetailed(
            "https://backend-b.example", request
        );

        assertThat(result.status()).isEqualTo(409);
        assertThat(result.body().getReason()).isEqualTo("CHECKIN_DELEGATION_LOOP");
        verify(hostResolver, org.mockito.Mockito.never()).resolve("backend-b.example");
        verify(transport, org.mockito.Mockito.never()).post(org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }
}
