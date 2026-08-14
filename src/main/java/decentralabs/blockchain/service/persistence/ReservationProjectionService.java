package decentralabs.blockchain.service.persistence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.net.URI;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.security.MessageDigest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.StaticGasProvider;

/**
 * Serves the reservation projection consumed by reservation automation on Lite
 * gateways. The credential is scoped to one gateway origin and is never
 * allowed to choose an arbitrary set of labs at request time.
 */
@Service
@Slf4j
public class ReservationProjectionService {

    private static final int MAX_LIMIT = 500;
    private static final String DEFAULT_CREDENTIALS = "{}";

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final WalletService walletService;

    @Value("${security.reservation-projection.credentials-json:{}}")
    private String credentialsJson = DEFAULT_CREDENTIALS;

    @Value("${contract.address:}")
    private String contractAddress = "";

    private final AtomicReference<Diamond> cachedDiamond = new AtomicReference<>();

    public ReservationProjectionService(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        ObjectMapper objectMapper,
        WalletService walletService
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.objectMapper = objectMapper;
        this.walletService = walletService;
    }

    public record ProjectionCredential(String gatewayId, String token, String accessUri) { }

    public record ReservationProjection(
        String transactionHash,
        String labId,
        String startTime,
        String endTime,
        String status
    ) { }

    private record ReservationRow(
        String transactionHash,
        String labId,
        Instant startTime,
        Instant endTime,
        String status,
        String accessUri
    ) { }

    public ProjectionCredential authenticate(String gatewayId, String token) {
        String normalizedGatewayId = normalizeGatewayId(gatewayId);
        if (!StringUtils.hasText(normalizedGatewayId) || !StringUtils.hasText(token)) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(
                StringUtils.hasText(credentialsJson) ? credentialsJson : DEFAULT_CREDENTIALS
            );
            JsonNode credential = root == null ? null : root.get(normalizedGatewayId);
            if (credential == null || !credential.isObject()) {
                return null;
            }
            String expectedToken = text(credential.get("token"));
            String accessUri = normalizeAccessUri(text(credential.get("accessUri")));
            if (!StringUtils.hasText(expectedToken) || !StringUtils.hasText(accessUri)
                || !constantTimeEquals(expectedToken, token.trim())) {
                return null;
            }
            return new ProjectionCredential(normalizedGatewayId, expectedToken, accessUri);
        } catch (Exception ex) {
            log.error("Invalid reservation projection credential configuration", ex);
            return null;
        }
    }

    public List<ReservationProjection> findReservations(
        ProjectionCredential credential,
        Instant from,
        Instant to,
        int requestedLimit
    ) {
        if (jdbcTemplate == null) {
            throw new IllegalStateException("Reservation projection database is not configured");
        }
        if (credential == null || from == null || to == null || from.isAfter(to)) {
            return List.of();
        }
        int limit = Math.max(1, Math.min(requestedLimit, MAX_LIMIT));
        String accessUri = credential.accessUri();
        String accessUriWithoutSlash = accessUri.endsWith("/")
            ? accessUri.substring(0, accessUri.length() - 1)
            : accessUri;
        String accessUriWithPath = accessUriWithoutSlash + "/%";

        List<ReservationRow> rows = jdbcTemplate.query(
            """
            SELECT transaction_hash, lab_id, start_time, end_time, status, access_uri
            FROM lab_reservations
            WHERE status IN ('CONFIRMED', 'ACTIVE')
              AND end_time >= ?
              AND start_time <= ?
              AND (
                  access_uri IS NULL
                  OR access_uri = ?
                  OR access_uri = ?
                  OR access_uri LIKE ?
              )
            ORDER BY start_time ASC
            LIMIT ?
            """,
            ps -> {
                ps.setTimestamp(1, Timestamp.from(from));
                ps.setTimestamp(2, Timestamp.from(to));
                ps.setString(3, accessUri);
                ps.setString(4, accessUriWithoutSlash);
                ps.setString(5, accessUriWithPath);
                ps.setInt(6, Math.min(MAX_LIMIT * 2, Math.max(limit, limit * 4)));
            },
            (rs, rowNum) -> new ReservationRow(
                rs.getString("transaction_hash"),
                rs.getString("lab_id"),
                instant(rs.getTimestamp("start_time")),
                instant(rs.getTimestamp("end_time")),
                rs.getString("status"),
                rs.getString("access_uri")
            )
        );

        List<ReservationProjection> projections = new ArrayList<>();
        for (ReservationRow row : rows) {
            String resolvedAccessUri = normalizeAccessUri(row.accessUri());
            if (resolvedAccessUri == null && StringUtils.hasText(row.labId())) {
                resolvedAccessUri = resolveLegacyAccessUri(row);
            }
            if (!accessUri.equals(resolvedAccessUri)) {
                continue;
            }
            projections.add(new ReservationProjection(
                row.transactionHash(),
                row.labId(),
                row.startTime() == null ? null : row.startTime().toString(),
                row.endTime() == null ? null : row.endTime().toString(),
                row.status()
            ));
            if (projections.size() >= limit) {
                break;
            }
        }
        return projections;
    }

    private String resolveLegacyAccessUri(ReservationRow row) {
        try {
            if (!StringUtils.hasText(contractAddress) || walletService == null) {
                return null;
            }
            BigInteger labId = new BigInteger(row.labId());
            Diamond.Lab lab = diamond().getLab(labId).send();
            String accessUri = lab == null || lab.base == null ? null : lab.base.accessURI;
            String normalized = normalizeAccessUri(accessUri);
            if (normalized != null) {
                jdbcTemplate.update(
                    "UPDATE lab_reservations SET access_uri = ? WHERE transaction_hash = ? AND access_uri IS NULL",
                    normalized,
                    row.transactionHash()
                );
            }
            return normalized;
        } catch (Exception ex) {
            log.warn(
                "Unable to resolve accessURI for legacy reservation {}: {}",
                row.transactionHash(),
                ex.getMessage()
            );
            return null;
        }
    }

    private Diamond diamond() {
        Diamond existing = cachedDiamond.get();
        if (existing != null) {
            return existing;
        }
        var web3j = walletService.getWeb3jInstance();
        if (web3j == null) {
            throw new IllegalStateException("Web3j instance is unavailable");
        }
        Diamond loaded = Diamond.load(
            contractAddress,
            web3j,
            new ReadonlyTransactionManager(web3j, contractAddress),
            new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );
        if (cachedDiamond.compareAndSet(null, loaded)) {
            return loaded;
        }
        return Objects.requireNonNull(cachedDiamond.get());
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    private static String text(JsonNode node) {
        return node != null && node.isTextual() ? node.asText().trim() : null;
    }

    private static String normalizeGatewayId(String gatewayId) {
        return gatewayId == null ? null : gatewayId.trim().toLowerCase(Locale.ROOT);
    }

    static String normalizeAccessUri(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            URI uri = URI.create(value.trim());
            if (!StringUtils.hasText(uri.getScheme()) || !StringUtils.hasText(uri.getHost())
                || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null) {
                return null;
            }
            String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
            if (!"https".equals(scheme)) {
                return null;
            }
            String host = uri.getHost().toLowerCase(Locale.ROOT);
            int port = uri.getPort();
            boolean defaultPort = port < 0 || ("https".equals(scheme) && port == 443)
                || ("http".equals(scheme) && port == 80);
            return scheme + "://" + host + (defaultPort ? "" : ":" + port);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
            expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            actual.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
    }
}
