package decentralabs.blockchain.service.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInStatusRequest;
import decentralabs.blockchain.service.BackendUrlResolver;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Dns;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

/** Outbound institutional check-in client with SSRF validation and DNS pinning. */
@Service
@Slf4j
public class RemoteInstitutionalCheckInClient {
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final long MAX_RESPONSE_BYTES = 1024 * 1024;

    private final ObjectMapper objectMapper;
    private final HostResolver hostResolver;
    private final PinnedTransport transport;
    private final OkHttpClient baseHttpClient;
    private final BackendUrlResolver backendUrlResolver;

    @Value("${institutional.checkin.delegation.endpoint-path:${endpoint.checkin-institutional:/auth/checkin-institutional}}")
    private String endpointPath;

    @Value("${institutional.checkin.delegation.allow-http:false}")
    private boolean allowHttp;

    @Value("${institutional.checkin.delegation.allow-private-networks:false}")
    private boolean allowPrivateNetworks;

    @Value("${institutional.checkin.delegation.status-endpoint-path:/auth/checkin-institutional/status}")
    private String statusEndpointPath;

    @Value("${public.base-url:}")
    private String configuredPublicBaseUrl;

    @Autowired
    public RemoteInstitutionalCheckInClient(ObjectMapper objectMapper, BackendUrlResolver backendUrlResolver) {
        this.objectMapper = objectMapper;
        this.backendUrlResolver = backendUrlResolver;
        this.hostResolver = hostname -> List.of(InetAddress.getAllByName(hostname));
        this.baseHttpClient = new OkHttpClient.Builder()
            .connectTimeout(Duration.ofSeconds(5))
            .readTimeout(Duration.ofSeconds(10))
            .followRedirects(false)
            .followSslRedirects(false)
            .build();
        this.transport = this::postPinned;
    }

    public RemoteInstitutionalCheckInClient(ObjectMapper objectMapper) {
        this(objectMapper, null);
    }

    RemoteInstitutionalCheckInClient(
        ObjectMapper objectMapper,
        HostResolver hostResolver,
        PinnedTransport transport
    ) {
        this(objectMapper, null, hostResolver, transport);
    }

    RemoteInstitutionalCheckInClient(
        ObjectMapper objectMapper,
        BackendUrlResolver backendUrlResolver,
        HostResolver hostResolver,
        PinnedTransport transport
    ) {
        this.objectMapper = objectMapper;
        this.backendUrlResolver = backendUrlResolver;
        this.hostResolver = hostResolver;
        this.transport = transport;
        this.baseHttpClient = null;
    }

    public CheckInResponse submit(String backendBaseUrl, InstitutionalCheckInRequest request) {
        RemoteCheckInResult result = submitDetailed(backendBaseUrl, request);
        if (!result.isHttpSuccessful()) {
            throw new RemoteInstitutionalCheckInException(result);
        }
        if (result.body() == null) {
            throw new IllegalStateException("Remote institutional check-in returned an empty response");
        }
        return result.body();
    }

    public RemoteCheckInResult submitDetailed(
        String backendBaseUrl,
        InstitutionalCheckInRequest request
    ) {
        URI endpoint = buildEndpoint(backendBaseUrl);
        if (isSelfDelegation(backendBaseUrl)) {
            return selfDelegationResult();
        }
        try {
            List<InetAddress> addresses = hostResolver.resolve(endpoint.getHost());
            assertAddressesAllowed(endpoint.getHost(), addresses);
            RemoteCheckInResult response = transport.post(endpoint, request, List.copyOf(addresses));
            if (response == null) {
                throw new IllegalStateException("Remote institutional check-in returned an empty response");
            }
            return response;
        } catch (IllegalArgumentException | SecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("Remote institutional check-in request failed for {}", endpoint.getHost());
            throw new IllegalStateException("Remote institutional check-in failed", ex);
        }
    }

    public RemoteCheckInResult queryStatus(
        String backendBaseUrl,
        InstitutionalCheckInStatusRequest request
    ) {
        URI endpoint = buildEndpoint(backendBaseUrl, statusEndpointPath());
        if (isSelfDelegation(backendBaseUrl, statusEndpointPath())) {
            return selfDelegationResult();
        }
        try {
            List<InetAddress> addresses = hostResolver.resolve(endpoint.getHost());
            assertAddressesAllowed(endpoint.getHost(), addresses);
            RemoteCheckInResult response = transport.post(endpoint, request, List.copyOf(addresses));
            if (response == null) {
                throw new IllegalStateException("Remote institutional check-in status returned an empty response");
            }
            return response;
        } catch (IllegalArgumentException | SecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("Remote institutional check-in status request failed for {}", endpoint.getHost());
            throw new IllegalStateException("Remote institutional check-in status failed", ex);
        }
    }

    private RemoteCheckInResult postPinned(
        URI endpoint,
        Object requestPayload,
        List<InetAddress> addresses
    ) throws Exception {
        String expectedHost = endpoint.getHost();
        Dns pinnedDns = hostname -> {
            if (!expectedHost.equalsIgnoreCase(hostname)) {
                throw new UnknownHostException("Cross-host DNS lookup refused");
            }
            return addresses;
        };
        OkHttpClient client = baseHttpClient.newBuilder().dns(pinnedDns).build();
        byte[] json = objectMapper.writeValueAsBytes(requestPayload);
        Request request = new Request.Builder()
            .url(endpoint.toString())
            .post(RequestBody.create(json, JSON))
            .header("Accept", "application/json")
            .build();

        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            if (body != null && body.contentLength() > MAX_RESPONSE_BYTES) {
                throw new IllegalStateException("Remote institutional check-in response is too large");
            }
            byte[] bytes = readResponseBytes(body);
            CheckInResponse parsed = parseOptionalResponse(bytes);
            return new RemoteCheckInResult(response.code(), parsed, response.header("Retry-After"));
        }
    }

    private byte[] readResponseBytes(ResponseBody body) throws IOException {
        if (body == null) {
            return new byte[0];
        }
        try (InputStream input = body.byteStream(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                if ((long) output.size() + read > MAX_RESPONSE_BYTES) {
                    throw new IllegalStateException("Remote institutional check-in response is too large");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private CheckInResponse parseOptionalResponse(byte[] bytes) {
        if (bytes.length == 0) {
            return null;
        }
        try {
            return objectMapper.readValue(bytes, CheckInResponse.class);
        } catch (IOException ex) {
            log.debug("Remote institutional check-in returned a non-JSON response body");
            return null;
        }
    }

    private RemoteCheckInResult selfDelegationResult() {
        CheckInResponse response = new CheckInResponse();
        response.setValid(false);
        response.setReason("CHECKIN_SIGNER_NOT_AUTHORIZED");
        response.setRetryable(false);
        return new RemoteCheckInResult(409, response, null);
    }

    private boolean isSelfDelegation(String backendBaseUrl) {
        return isSelfDelegation(backendBaseUrl, delegationEndpointPath());
    }

    private boolean isSelfDelegation(String backendBaseUrl, String endpointPathForComparison) {
        String target = normalizeBaseUrl(backendBaseUrl, endpointPathForComparison);
        if (target == null) {
            return false;
        }
        if (normalizeBaseUrl(configuredPublicBaseUrl, endpointPathForComparison) != null
            && target.equals(normalizeBaseUrl(configuredPublicBaseUrl, endpointPathForComparison))) {
            return true;
        }
        return backendUrlResolver != null
            && target.equals(normalizeBaseUrl(backendUrlResolver.resolveBaseDomain(), endpointPathForComparison));
    }

    private String normalizeBaseUrl(String value, String endpointPathForComparison) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            URI uri = URI.create(value.trim());
            if (uri.getScheme() == null || uri.getHost() == null
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                || uri.getRawFragment() != null) {
                return null;
            }
            String scheme = uri.getScheme().toLowerCase();
            String host = uri.getHost().toLowerCase();
            int port = uri.getPort();
            boolean defaultPort = port < 0
                || ("https".equals(scheme) && port == 443)
                || ("http".equals(scheme) && port == 80);
            String path = uri.getPath() == null ? "" : uri.getPath();
            while (path.endsWith("/") && !path.isEmpty()) {
                path = path.substring(0, path.length() - 1);
            }
            path = normalizeBasePath(path, endpointPathForComparison);
            String authority = scheme + "://" + host + (defaultPort ? "" : ":" + port);
            return authority + path;
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private URI buildEndpoint(String backendBaseUrl) {
        return buildEndpoint(backendBaseUrl, delegationEndpointPath());
    }

    private URI buildEndpoint(String backendBaseUrl, String endpointPath) {
        if (backendBaseUrl == null || backendBaseUrl.isBlank()) {
            throw new IllegalArgumentException("Missing remote institutional backend URL");
        }
        URI baseUri;
        try {
            baseUri = URI.create(backendBaseUrl.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid remote institutional backend URL", ex);
        }
        String scheme = baseUri.getScheme();
        boolean https = "https".equalsIgnoreCase(scheme);
        if (!https && !(allowHttp && "http".equalsIgnoreCase(scheme))) {
            throw new IllegalArgumentException("Remote institutional backend URL must use HTTPS");
        }
        if (baseUri.getHost() == null || baseUri.getRawUserInfo() != null
            || baseUri.getRawQuery() != null || baseUri.getRawFragment() != null) {
            throw new IllegalArgumentException("Remote institutional backend URL contains forbidden components");
        }
        return UriComponentsBuilder.fromUri(baseUri)
            .replacePath(joinPath(normalizeBasePath(baseUri.getPath(), endpointPath), endpointPath))
            .replaceQuery(null)
            .fragment(null)
            .build(true)
            .toUri();
    }

    private void assertAddressesAllowed(String hostname, List<InetAddress> addresses) {
        String normalizedHost = hostname == null ? "" : hostname.toLowerCase();
        if (allowPrivateNetworks) {
            return;
        }
        if (normalizedHost.equals("localhost") || normalizedHost.endsWith(".local")
            || normalizedHost.endsWith(".internal")) {
            throw new SecurityException("Remote institutional backend host is not public");
        }
        if (addresses == null || addresses.isEmpty() || addresses.stream().anyMatch(this::isNonPublicAddress)) {
            throw new SecurityException("Remote institutional backend DNS resolved to a non-public address");
        }
    }

    private boolean isNonPublicAddress(InetAddress address) {
        if (address == null || address.isAnyLocalAddress() || address.isLoopbackAddress()
            || address.isLinkLocalAddress() || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            return isNonPublicIpv4(bytes);
        }
        if (bytes.length != 16) {
            return true;
        }
        if (isIpv4Mapped(bytes)) {
            return true;
        }
        int first = unsigned(bytes[0]);
        if ((first & 0xe0) != 0x20) {
            return true; // Only global-unicast 2000::/3 can be public here.
        }
        return hasPrefix(bytes, new int[] {0x20, 0x01, 0x0d, 0xb8}, 32)
            || hasPrefix(bytes, new int[] {0x20, 0x01, 0x00}, 23)
            || hasPrefix(bytes, new int[] {0x20, 0x02}, 16)
            || hasPrefix(bytes, new int[] {0x3f, 0xff, 0x00}, 20);
    }

    private boolean isNonPublicIpv4(byte[] bytes) {
        int a = unsigned(bytes[0]);
        int b = unsigned(bytes[1]);
        int c = unsigned(bytes[2]);
        return a == 0 || a == 10 || a == 127 || a >= 224
            || (a == 100 && b >= 64 && b <= 127)
            || (a == 169 && b == 254)
            || (a == 172 && b >= 16 && b <= 31)
            || (a == 192 && b == 168)
            || (a == 192 && b == 0 && c == 0)
            || (a == 192 && b == 0 && c == 2)
            || (a == 192 && b == 31 && c == 196)
            || (a == 192 && b == 52 && c == 193)
            || (a == 192 && b == 88 && c == 99)
            || (a == 192 && b == 175 && c == 48)
            || (a == 198 && (b == 18 || b == 19))
            || (a == 198 && b == 51 && c == 100)
            || (a == 203 && b == 0 && c == 113);
    }

    private boolean isIpv4Mapped(byte[] bytes) {
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) return false;
        }
        return unsigned(bytes[10]) == 0xff && unsigned(bytes[11]) == 0xff;
    }

    private boolean hasPrefix(byte[] address, int[] prefix, int bits) {
        int fullBytes = bits / 8;
        int remainingBits = bits % 8;
        for (int i = 0; i < fullBytes; i++) {
            if (unsigned(address[i]) != prefix[i]) return false;
        }
        if (remainingBits == 0) return true;
        int mask = 0xff << (8 - remainingBits);
        return (unsigned(address[fullBytes]) & mask) == (prefix[fullBytes] & mask);
    }

    private int unsigned(byte value) {
        return value & 0xff;
    }

    private String normalizeBasePath(String basePath, String endpoint) {
        String normalized = basePath == null ? "" : basePath.trim();
        if (endpoint.startsWith("/auth/") && normalized.endsWith("/api")) {
            return normalized.substring(0, normalized.length() - "/api".length());
        }
        if ("/api".equals(normalized) || "/auth".equals(normalized)) {
            return "";
        }
        return normalized;
    }

    private String delegationEndpointPath() {
        return endpointPath == null || endpointPath.isBlank()
            ? "/auth/checkin-institutional" : endpointPath;
    }

    private String statusEndpointPath() {
        return statusEndpointPath == null || statusEndpointPath.isBlank()
            ? "/auth/checkin-institutional/status" : statusEndpointPath;
    }

    private String joinPath(String basePath, String path) {
        String left = basePath == null ? "" : basePath.trim();
        String right = path.trim();
        if (left.endsWith("/")) left = left.substring(0, left.length() - 1);
        if (!right.startsWith("/")) right = "/" + right;
        return left + right;
    }

    @FunctionalInterface
    interface HostResolver {
        List<InetAddress> resolve(String hostname) throws Exception;
    }

    @FunctionalInterface
    interface PinnedTransport {
        RemoteCheckInResult post(URI endpoint, Object request, List<InetAddress> addresses)
            throws Exception;
    }

    public record RemoteCheckInResult(int status, CheckInResponse body, String retryAfter) {
        public static RemoteCheckInResult success(CheckInResponse body) {
            return new RemoteCheckInResult(200, body, null);
        }

        public boolean isSuccessful() {
            return isHttpSuccessful() && body != null && body.isValid();
        }

        public boolean isHttpSuccessful() {
            return status >= 200 && status < 300;
        }

        public boolean isRetryable() {
            if (body != null && body.getRetryable() != null) {
                return body.getRetryable();
            }
            return status == 429 || status == 502 || status == 503 || status == 504;
        }
    }
}
