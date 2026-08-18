package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInStatusRequest;
import java.net.InetAddress;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RemoteInstitutionalCheckInClientTest {
    @Mock private RemoteInstitutionalCheckInClient.HostResolver hostResolver;
    @Mock private RemoteInstitutionalCheckInClient.PinnedTransport transport;
    private RemoteInstitutionalCheckInClient client;
    private InetAddress publicAddress;

    @BeforeEach
    void setUp() throws Exception {
        publicAddress = InetAddress.getByAddress("institution.example", new byte[] {93, (byte) 184, (byte) 216, 34});
        client = new RemoteInstitutionalCheckInClient(new ObjectMapper(), hostResolver, transport);
        lenient().when(hostResolver.resolve("institution.example")).thenReturn(List.of(publicAddress));
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

}
