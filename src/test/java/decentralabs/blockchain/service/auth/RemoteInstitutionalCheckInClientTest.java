package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.service.BackendUrlResolver;
import java.net.InetAddress;
import java.net.URI;
import java.util.List;
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
}
