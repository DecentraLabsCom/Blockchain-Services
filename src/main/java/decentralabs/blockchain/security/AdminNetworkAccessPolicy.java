package decentralabs.blockchain.security;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Centralizes localhost/private-network checks for dashboard and wallet admin routes.
 */
@Component
@Slf4j
public class AdminNetworkAccessPolicy {

    @Value("${admin.dashboard.local-only:true}")
    private boolean adminDashboardLocalOnly;

    @Value("${admin.dashboard.allow-private:false}")
    private boolean adminDashboardAllowPrivate;

    @Value("${security.allow-private-networks:false}")
    private boolean allowPrivateNetworks;

    @Value("${security.access-token.required:true}")
    private boolean accessTokenRequired;

    @Value("${admin.dashboard.allowed-cidrs:}")
    private String configuredCidrs;

    public boolean isRequestAllowed(HttpServletRequest request, BooleanSupplier validTokenSupplier) {
        if (!adminDashboardLocalOnly) {
            return true;
        }

        if (matchesLoopback(request)) {
            return true;
        }

        if (!adminDashboardAllowPrivate || !allowPrivateNetworks || !matchesPrivateAccessNetwork(request)) {
            return false;
        }

        return !accessTokenRequired || validTokenSupplier.getAsBoolean();
    }

    public boolean isLocalOnly() {
        return adminDashboardLocalOnly;
    }

    public boolean isPrivateAccessEnabled() {
        return adminDashboardAllowPrivate && allowPrivateNetworks;
    }

    public List<String> getConfiguredCidrs() {
        List<String> cidrs = new ArrayList<>();
        for (String token : configuredCidrs.split(",")) {
            String value = token == null ? "" : token.trim();
            if (!value.isEmpty()) {
                cidrs.add(value);
            }
        }
        return cidrs;
    }

    private boolean matchesLoopback(HttpServletRequest request) {
        for (String candidate : getTrustedClientCandidates(request)) {
            if (isLoopback(candidate)) {
                return true;
            }
        }
        return false;
    }

    private boolean matchesPrivateAccessNetwork(HttpServletRequest request) {
        List<CidrRange> cidrs = parseCidrs();
        for (String candidate : getTrustedClientCandidates(request)) {
            if (candidate == null || candidate.isBlank() || isLoopback(candidate)) {
                continue;
            }
            if (cidrs.isEmpty()) {
                if (isBroadPrivateAddress(candidate)) {
                    return true;
                }
                continue;
            }
            if (cidrs.stream().anyMatch(cidr -> cidr.matches(candidate))) {
                return true;
            }
        }
        return false;
    }

    private List<String> getTrustedClientCandidates(HttpServletRequest request) {
        Set<String> candidates = new LinkedHashSet<>();
        String remoteAddr = sanitizeIp(request.getRemoteAddr());
        if (remoteAddr != null) {
            candidates.add(remoteAddr);
        }

        if (remoteAddr != null && (isLoopback(remoteAddr) || isBroadPrivateAddress(remoteAddr))) {
            addForwardedCandidates(candidates, request.getHeader("X-Forwarded-For"));
            String realIp = sanitizeIp(request.getHeader("X-Real-IP"));
            if (realIp != null) {
                candidates.add(realIp);
            }
        }

        return new ArrayList<>(candidates);
    }

    private void addForwardedCandidates(Set<String> candidates, String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return;
        }
        for (String token : headerValue.split(",")) {
            String candidate = sanitizeIp(token);
            if (candidate != null) {
                candidates.add(candidate);
            }
        }
    }

    private String sanitizeIp(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private boolean isLoopback(String address) {
        try {
            return InetAddress.getByName(address).isLoopbackAddress();
        } catch (Exception ex) {
            return false;
        }
    }

    private boolean isBroadPrivateAddress(String address) {
        try {
            InetAddress inetAddress = InetAddress.getByName(address);
            return inetAddress.isSiteLocalAddress()
                || inetAddress.isLinkLocalAddress()
                || isUniqueLocalIpv6(address);
        } catch (Exception ex) {
            return false;
        }
    }

    private boolean isUniqueLocalIpv6(String address) {
        String normalized = address.toLowerCase();
        return normalized.startsWith("fc") || normalized.startsWith("fd");
    }

    private List<CidrRange> parseCidrs() {
        List<CidrRange> ranges = new ArrayList<>();
        for (String token : getConfiguredCidrs()) {
            CidrRange range = CidrRange.tryParse(token);
            if (range != null) {
                ranges.add(range);
            } else {
                log.warn("Ignoring invalid ADMIN_ALLOWED_CIDRS entry: {}", token);
            }
        }
        return ranges;
    }

    private record CidrRange(byte[] networkBytes, int prefixLength) {
        static CidrRange tryParse(String raw) {
            if (raw == null || raw.isBlank() || !raw.contains("/")) {
                return null;
            }
            try {
                String[] parts = raw.trim().split("/", 2);
                InetAddress network = InetAddress.getByName(parts[0].trim());
                int prefixLength = Integer.parseInt(parts[1].trim());
                int bitLength = network.getAddress().length * 8;
                if (prefixLength < 0 || prefixLength > bitLength) {
                    return null;
                }
                return new CidrRange(network.getAddress(), prefixLength);
            } catch (Exception ex) {
                return null;
            }
        }

        boolean matches(String candidate) {
            try {
                byte[] candidateBytes = InetAddress.getByName(candidate).getAddress();
                if (candidateBytes.length != networkBytes.length) {
                    return false;
                }
                int remainingBits = prefixLength;
                for (int i = 0; i < networkBytes.length && remainingBits > 0; i++) {
                    int mask = remainingBits >= 8 ? 0xFF : 0xFF << (8 - remainingBits);
                    if ((candidateBytes[i] & mask) != (networkBytes[i] & mask)) {
                        return false;
                    }
                    remainingBits -= 8;
                }
                return true;
            } catch (Exception ex) {
                return false;
            }
        }
    }
}
