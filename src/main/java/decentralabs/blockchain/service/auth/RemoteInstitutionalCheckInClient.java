package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import java.net.URI;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Service
@RequiredArgsConstructor
@Slf4j
public class RemoteInstitutionalCheckInClient {
    private final RestTemplate restTemplate;

    @Value("${institutional.checkin.delegation.endpoint-path:${endpoint.checkin-institutional:/auth/checkin-institutional}}")
    private String endpointPath;

    public CheckInResponse submit(String backendBaseUrl, InstitutionalCheckInRequest request) {
        URI endpoint = buildEndpoint(backendBaseUrl);
        try {
            ResponseEntity<CheckInResponse> response = restTemplate.postForEntity(endpoint, request, CheckInResponse.class);
            CheckInResponse body = response.getBody();
            if (!response.getStatusCode().is2xxSuccessful() || body == null) {
                throw new IllegalStateException("Remote institutional check-in failed with status " + response.getStatusCode());
            }
            return body;
        } catch (RestClientException ex) {
            log.warn("Remote institutional check-in request failed for {}: {}", endpoint.getHost(), ex.getMessage());
            throw new IllegalStateException("Remote institutional check-in failed: " + ex.getMessage(), ex);
        }
    }

    private URI buildEndpoint(String backendBaseUrl) {
        if (backendBaseUrl == null || backendBaseUrl.isBlank()) {
            throw new IllegalArgumentException("Missing remote institutional backend URL");
        }
        String base = backendBaseUrl.trim();
        URI baseUri = URI.create(base);
        String scheme = baseUri.getScheme();
        if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("Unsupported remote institutional backend URL scheme");
        }
        String path = endpointPath == null || endpointPath.isBlank() ? "/auth/checkin-institutional" : endpointPath;
        return UriComponentsBuilder.fromUri(baseUri)
            .replacePath(joinPath(normalizeBasePath(baseUri.getPath(), path), path))
            .replaceQuery(null)
            .build(true)
            .toUri();
    }

    private String normalizeBasePath(String basePath, String endpoint) {
        String normalized = basePath == null ? "" : basePath.trim();
        if (endpoint.startsWith("/auth/") && normalized.endsWith("/api")) {
            return normalized.substring(0, normalized.length() - "/api".length());
        }
        return normalized;
    }

    private String joinPath(String basePath, String path) {
        String left = basePath == null ? "" : basePath.trim();
        String right = path.trim();
        if (left.endsWith("/")) {
            left = left.substring(0, left.length() - 1);
        }
        if (!right.startsWith("/")) {
            right = "/" + right;
        }
        return left + right;
    }
}
