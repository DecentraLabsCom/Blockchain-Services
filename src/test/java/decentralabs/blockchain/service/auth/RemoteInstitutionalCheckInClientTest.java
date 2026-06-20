package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import java.net.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

@ExtendWith(MockitoExtension.class)
class RemoteInstitutionalCheckInClientTest {
    @Mock
    private RestTemplate restTemplate;

    private RemoteInstitutionalCheckInClient client;

    @BeforeEach
    void setUp() {
        client = new RemoteInstitutionalCheckInClient(restTemplate);
        ReflectionTestUtils.setField(client, "endpointPath", "/auth/checkin-institutional");
    }

    @Test
    void submitShouldCallAuthEndpointWhenRegisteredBackendUrlEndsWithApi() {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        CheckInResponse expected = new CheckInResponse();
        expected.setValid(true);

        when(restTemplate.postForEntity(
            eq(URI.create("https://institution.example/auth/checkin-institutional")),
            eq(request),
            eq(CheckInResponse.class)
        )).thenReturn(ResponseEntity.ok(expected));

        CheckInResponse response = client.submit("https://institution.example/api", request);

        assertThat(response).isSameAs(expected);
        verify(restTemplate).postForEntity(
            eq(URI.create("https://institution.example/auth/checkin-institutional")),
            eq(request),
            eq(CheckInResponse.class)
        );
    }

    @Test
    void submitShouldPreserveNonApiBasePath() {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        CheckInResponse expected = new CheckInResponse();
        expected.setValid(true);
        ArgumentCaptor<URI> uriCaptor = ArgumentCaptor.forClass(URI.class);

        when(restTemplate.postForEntity(uriCaptor.capture(), eq(request), eq(CheckInResponse.class)))
            .thenReturn(ResponseEntity.ok(expected));

        CheckInResponse response = client.submit("https://institution.example/gateway", request);

        assertThat(response).isSameAs(expected);
        assertThat(uriCaptor.getValue()).isEqualTo(URI.create("https://institution.example/gateway/auth/checkin-institutional"));
    }
}
