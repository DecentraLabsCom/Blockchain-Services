package decentralabs.blockchain.service.health;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import jakarta.annotation.PostConstruct;
import okhttp3.Dns;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Security boundary for metadata documents referenced by on-chain lab data.
 *
 * <p>Remote documents are HTTPS-only, must use an exact registered provider
 * origin, are fetched through a DNS-pinned client, and are bounded by response
 * size, redirects and timeouts. Local files are fixtures only and must stay
 * below the configured metadata root.</p>
 */
@Component
public class SafeLabMetadataClient {

    public static final long DEFAULT_MAX_BYTES = 1024L * 1024L;
    private static final int MAX_REDIRECTS = 3;
    private static final int MAX_DNS_ADDRESSES = 32;
    private static final int DEFAULT_MAX_CONCURRENT_FETCHES = 8;

    @Value("${lab.metadata.max-bytes:1048576}")
    private long maxBytes = DEFAULT_MAX_BYTES;

    @Value("${lab.metadata.http.connect-timeout-ms:5000}")
    private long connectTimeoutMs = 5000L;

    @Value("${lab.metadata.http.read-timeout-ms:10000}")
    private long readTimeoutMs = 10000L;

    @Value("${lab.metadata.http.call-timeout-ms:15000}")
    private long callTimeoutMs = 15000L;

    @Value("${lab.metadata.local.enabled:false}")
    private boolean localMetadataEnabled;

    @Value("${lab.metadata.local.root:/app/lab-metadata-fixtures}")
    private String localMetadataRoot = "/app/lab-metadata-fixtures";

    @Value("${lab.metadata.max-concurrent-fetches:8}")
    private int maxConcurrentFetches = DEFAULT_MAX_CONCURRENT_FETCHES;

    private Semaphore fetchSlots = new Semaphore(DEFAULT_MAX_CONCURRENT_FETCHES, true);

    @PostConstruct
    void initialize() {
        if (maxBytes <= 0 || connectTimeoutMs <= 0 || readTimeoutMs <= 0 || callTimeoutMs <= 0) {
            throw new IllegalStateException("Lab metadata limits and timeouts must be positive");
        }
        if (maxConcurrentFetches <= 0) {
            throw new IllegalStateException("lab.metadata.max-concurrent-fetches must be positive");
        }
        fetchSlots = new Semaphore(maxConcurrentFetches, true);
    }

    /**
     * Loads raw JSON bytes from a local fixture or an allowlisted remote origin.
     */
    public byte[] fetch(String metadataUri, Collection<String> allowedOrigins) {
        try {
            return fetchChecked(metadataUri, allowedOrigins);
        } catch (IOException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }

    /**
     * Loads a display-only document from the exact HTTPS URI stored on-chain.
     *
     * <p>This is intentionally separate from {@link #fetch(String, Collection)}:
     * normal metadata reads require a provider-registered origin, while an
     * on-chain URI may point to a public content-addressed store such as a
     * Vercel Blob. The same HTTPS, DNS pinning, redirect, content-type and
     * response-size protections still apply.</p>
     */
    public byte[] fetchFromAuthoritativeUri(String metadataUri) {
        try {
            if (metadataUri == null || metadataUri.isBlank()) {
                throw new IOException("Metadata URI is empty");
            }
            URI candidate = parseUri(metadataUri.trim());
            if (!"https".equalsIgnoreCase(candidate.getScheme())) {
                throw new IOException("Authoritative lab metadata must use HTTPS");
            }
            return fetchRemote(candidate, origin(candidate));
        } catch (IOException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }

    private byte[] fetchChecked(String metadataUri, Collection<String> allowedOrigins) throws IOException {
        if (metadataUri == null || metadataUri.isBlank()) {
            throw new IOException("Metadata URI is empty");
        }

        URI candidate = parseUri(metadataUri.trim());
        if (candidate.getScheme() == null) {
            if (candidate.getRawQuery() != null || candidate.getRawAuthority() != null) {
                throw new IOException("Local metadata fixture must be a relative path without query parameters");
            }
            return readLocalFixture(candidate.getPath());
        }
        if (!"https".equalsIgnoreCase(candidate.getScheme())) {
            throw new IOException("Lab metadata must use HTTPS or an approved local fixture");
        }

        String expectedOrigin = exactAllowedOrigin(candidate, allowedOrigins);
        return fetchRemote(candidate, expectedOrigin);
    }

    private byte[] fetchRemote(URI initialUri, String expectedOrigin) throws IOException {
        boolean acquired = false;
        try {
            acquired = fetchSlots.tryAcquire(callTimeoutMs, TimeUnit.MILLISECONDS);
            if (!acquired) {
                throw new IOException("Metadata fetch concurrency limit reached");
            }

            URI current = initialUri;
            int redirectCount = 0;
            while (true) {
                URI requestUri = current;
                exactAllowedOrigin(requestUri, List.of(expectedOrigin));
                List<InetAddress> addresses = resolveAndValidate(requestUri.getHost());
                Dns pinnedDns = hostname -> {
                    if (!requestUri.getHost().equalsIgnoreCase(hostname)) {
                        throw new UnknownHostException("Cross-host DNS lookup refused");
                    }
                    return addresses;
                };

                OkHttpClient client = new OkHttpClient.Builder()
                    .connectTimeout(connectTimeoutMs, TimeUnit.MILLISECONDS)
                    .readTimeout(readTimeoutMs, TimeUnit.MILLISECONDS)
                    .callTimeout(callTimeoutMs, TimeUnit.MILLISECONDS)
                    .followRedirects(false)
                    .followSslRedirects(false)
                    .retryOnConnectionFailure(false)
                    .dns(pinnedDns)
                    .build();

                Request request = new Request.Builder()
                    .url(requestUri.toString())
                    .header("Accept", "application/json")
                    .header("User-Agent", "DecentraLabs-Blockchain-Services/1.0")
                    .build();

                try (Response response = client.newCall(request).execute()) {
                    if (response.isRedirect()) {
                        if (redirectCount >= MAX_REDIRECTS) {
                            throw new IOException("Metadata request exceeded the redirect limit");
                        }
                        String location = response.header("Location");
                        if (location == null || location.isBlank()) {
                            throw new IOException("Metadata redirect did not include a Location header");
                        }
                        URI redirected = parseUri(current.resolve(location).toString());
                        exactAllowedOrigin(redirected, List.of(expectedOrigin));
                        redirectCount++;
                        current = redirected;
                        continue;
                    }
                    if (!response.isSuccessful()) {
                        throw new IOException("Metadata request failed with HTTP " + response.code());
                    }
                    requireJsonContentType(response.header("Content-Type"));
                    return readBounded(response.body());
                }
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IOException("Metadata fetch was interrupted", ex);
        } finally {
            if (acquired) {
                fetchSlots.release();
            }
        }
    }

    private byte[] readLocalFixture(String relativePath) throws IOException {
        if (!localMetadataEnabled) {
            throw new IOException("Local lab metadata fixtures are disabled");
        }
        if (relativePath == null || relativePath.isBlank()) {
            throw new IOException("Local metadata path is empty");
        }

        Path root = Paths.get(localMetadataRoot).toAbsolutePath().normalize();
        Path candidate = root.resolve(relativePath).normalize();
        if (!candidate.startsWith(root) || Paths.get(relativePath).isAbsolute()) {
            throw new IOException("Local metadata path escapes the configured root");
        }
        if (!Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Local metadata fixture is not a regular file");
        }

        Path realRoot = root.toRealPath();
        Path realCandidate = candidate.toRealPath();
        if (!realCandidate.startsWith(realRoot)) {
            throw new IOException("Local metadata fixture escapes the configured root");
        }
        long size = Files.size(realCandidate);
        if (size > maxBytes) {
            throw new IOException("Metadata response exceeds the maximum size");
        }
        return Files.readAllBytes(realCandidate);
    }

    private static URI parseUri(String raw) throws IOException {
        try {
            URI uri = new URI(raw);
            if (uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
                throw new IOException("Metadata URI must not contain credentials or fragments");
            }
            return uri;
        } catch (URISyntaxException | IllegalArgumentException ex) {
            throw new IOException("Metadata URI is invalid", ex);
        }
    }

    private static String exactAllowedOrigin(URI uri, Collection<String> allowedOrigins) throws IOException {
        if (uri == null || uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IOException("Metadata URI must contain a valid host");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IOException("Metadata URI must use HTTPS");
        }
        String actual = origin(uri);
        if (allowedOrigins == null || allowedOrigins.stream().noneMatch(origin -> originEquals(actual, origin))) {
            throw new IOException("Metadata origin is not registered for this provider");
        }
        return actual;
    }

    private static boolean originEquals(String actual, String configured) {
        if (configured == null || configured.isBlank()) {
            return false;
        }
        try {
            URI parsed = new URI(configured.trim());
            return origin(parsed).equalsIgnoreCase(actual);
        } catch (Exception ex) {
            return false;
        }
    }

    private static String origin(URI uri) throws IOException {
        if (uri == null || uri.getHost() == null || uri.getRawUserInfo() != null
            || uri.getRawQuery() != null || uri.getRawFragment() != null
            || !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IOException("Registered metadata origin must be an HTTPS origin");
        }
        int port = uri.getPort() < 0 ? 443 : uri.getPort();
        if (port <= 0 || port > 65535) {
            throw new IOException("Registered metadata origin has an invalid port");
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (host.contains(":")) {
            host = "[" + host + "]";
        }
        return port == 443 ? "https://" + host : "https://" + host + ":" + port;
    }

    private List<InetAddress> resolveAndValidate(String host) throws IOException {
        List<InetAddress> addresses;
        try {
            addresses = List.of(InetAddress.getAllByName(host));
        } catch (Exception ex) {
            throw new IOException("Unable to resolve metadata host", ex);
        }
        if (addresses.size() > MAX_DNS_ADDRESSES) {
            throw new IOException("Metadata host returned an invalid number of addresses");
        }
        for (InetAddress address : addresses) {
            if (isBlockedAddress(address)) {
                throw new IOException("Metadata host resolves to a private or reserved address");
            }
        }
        return addresses;
    }

    private static boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
            || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            int a = Byte.toUnsignedInt(bytes[0]);
            int b = Byte.toUnsignedInt(bytes[1]);
            int c = Byte.toUnsignedInt(bytes[2]);
            return a == 0 || a == 10 || a == 127 || (a == 100 && b >= 64 && b <= 127)
                || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31)
                || (a == 192 && (b == 0 || b == 2 || b == 168))
                || (a == 192 && b == 31 && c == 196) || (a == 192 && b == 52 && c == 193)
                || (a == 192 && b == 88 && c == 99) || (a == 192 && b == 175 && c == 48)
                || (a == 198 && (b == 18 || b == 19 || b == 51))
                || (a == 203 && b == 0 && c == 113) || a >= 224;
        }

        if (address instanceof Inet6Address) {
            int first = Byte.toUnsignedInt(bytes[0]);
            int second = Byte.toUnsignedInt(bytes[1]);
            boolean uniqueLocal = (first & 0xFE) == 0xFC;
            boolean documentation = first == 0x20 && second == 0x01 && bytes[2] == 0x0d && bytes[3] == (byte) 0xb8;
            boolean mappedIpv4 = first == 0 && second == 0 && bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff;
            return uniqueLocal || documentation || mappedIpv4;
        }
        return true;
    }

    private void requireJsonContentType(String contentType) throws IOException {
        if (contentType == null || contentType.isBlank()) {
            throw new IOException("Metadata response must declare a JSON content type");
        }
        String mediaType = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        if (!"application/json".equals(mediaType) && !mediaType.endsWith("+json")) {
            throw new IOException("Metadata response must use a JSON content type");
        }
    }

    private byte[] readBounded(ResponseBody body) throws IOException {
        if (body == null) {
            throw new IOException("Metadata response body is empty");
        }
        if (body.contentLength() > maxBytes) {
            throw new IOException("Metadata response exceeds the maximum size");
        }
        try (InputStream input = body.byteStream(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                if ((long) output.size() + read > maxBytes) {
                    throw new IOException("Metadata response exceeds the maximum size");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }
}
