package decentralabs.blockchain.service.organization;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.organization.InstitutionInviteTokenRequest;
import decentralabs.blockchain.dto.organization.InstitutionInviteTokenResponse;
import decentralabs.blockchain.dto.organization.InstitutionInviteTokenResponse.DomainResult;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Convert;

@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionInviteService {

    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${contract.address}")
    private String diamondContractAddress;

    @Value("${ethereum.gas.limit.contract:100000}")
    private long contractGasLimit;

    @Value("${ethereum.gas.price.default:1}")
    private double defaultGasPriceGwei;

    @Value("${organization.invite.hmac-secret:}")
    private String inviteSecret;

    @Value("${organization.invite.default-issuer:}")
    private String defaultIssuer;

    private volatile Diamond cachedDiamond;

    public InstitutionInviteTokenResponse applyInvite(InstitutionInviteTokenRequest request) {
        InvitePayload payload = verifyToken(request.getToken());

        String localWallet = normalize(institutionalWalletService.getInstitutionalWalletAddress());
        String suppliedWallet = normalize(request.getWalletAddress());
        String targetWallet = !suppliedWallet.isBlank() ? suppliedWallet : localWallet;

        if (targetWallet.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Institutional wallet not configured yet.");
        }

        if (payload.institutionWallet != null
            && !normalize(payload.institutionWallet).isBlank()
            && !normalize(payload.institutionWallet).equals(targetWallet)) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Invite token was issued for a different wallet address."
            );
        }

        if (payload.organizations == null || payload.organizations.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invite token does not specify any organizations.");
        }

        List<DomainResult> results = new ArrayList<>();
        boolean allSuccess = true;

        for (String organization : payload.organizations) {
            String normalizedOrg = normalizeOrganization(organization);
            try {
                TransactionReceipt receipt = getAdminDiamond()
                    .grantInstitutionRole(targetWallet, normalizedOrg)
                    .send();

                results.add(DomainResult.builder()
                    .organization(normalizedOrg)
                    .transactionHash(receipt.getTransactionHash())
                    .build());
            } catch (Exception ex) {
                allSuccess = false;
                String sanitized = ex.getMessage() != null ? ex.getMessage() : ex.toString();
                log.warn("Unable to grant institution role for {}: {}", normalizedOrg, sanitized);
                results.add(DomainResult.builder()
                    .organization(normalizedOrg)
                    .error(sanitized)
                    .build());
            }
        }

        return InstitutionInviteTokenResponse.builder()
            .success(allSuccess)
            .walletAddress(targetWallet)
            .organizations(payload.organizations)
            .domains(results)
            .message(allSuccess
                ? "Institution registered successfully."
                : "Some organizations could not be registered. Review the errors.")
            .inviteId(payload.inviteId)
            .build();
    }

    public boolean isInviteConfigured() {
        return inviteSecret != null && !inviteSecret.isBlank();
    }

    private InvitePayload verifyToken(String token) {
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invite token cannot be empty.");
        }
        if (inviteSecret == null || inviteSecret.isBlank()) {
            throw new ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Invite secret not configured. Set organization.invite.hmac-secret."
            );
        }

        String[] parts = token.trim().split("\\.");
        if (parts.length != 2) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Malformed invite token.");
        }
        String payloadPart = parts[0];
        String signaturePart = parts[1];

        String expectedSignature = hmac(payloadPart, inviteSecret);
        if (!MessageDigest.isEqual(hexToBytes(expectedSignature), hexToBytes(signaturePart))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invite token signature mismatch.");
        }

        try {
            byte[] decoded = Base64.getUrlDecoder().decode(payloadPart);
            InvitePayload payload = objectMapper.readValue(decoded, InvitePayload.class);
            if (payload.expiresAt != null && Instant.now().isAfter(payload.expiresAt)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invite token has expired.");
            }
            if (payload.organizations == null || payload.organizations.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invite token is missing organizations.");
            }
            if (payload.issuer == null || payload.issuer.isBlank()) {
                payload.issuer = defaultIssuer;
            }
            return payload;
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Unable to parse invite token: " + ex.getMessage()
            );
        }
    }

    private String hmac(String payload, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] result = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(result.length * 2);
            for (byte b : result) {
                sb.append(String.format(Locale.ROOT, "%02x", b));
            }
            return sb.toString();
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Unable to verify invite token.");
        }
    }

    private byte[] hexToBytes(String value) {
        if (value == null) {
            return new byte[0];
        }
        String normalized = value.trim();
        int len = normalized.length();
        if (len % 2 != 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid invite signature length.");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(normalized.charAt(i), 16);
            int lo = Character.digit(normalized.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invite signature is not valid hex.");
            }
            data[i / 2] = (byte) ((hi << 4) + lo);
        }
        return data;
    }

    private Diamond getAdminDiamond() {
        Diamond local = cachedDiamond;
        if (local == null) {
            synchronized (this) {
                local = cachedDiamond;
                if (local == null) {
                    var web3j = walletService.getWeb3jInstance();
                    var gasPrice = Convert.toWei(
                        String.valueOf(defaultGasPriceGwei),
                        Convert.Unit.GWEI
                    ).toBigInteger();
                    local = Diamond.load(
                        diamondContractAddress,
                        web3j,
                        institutionalWalletService.getInstitutionalCredentials(),
                        new StaticGasProvider(gasPrice, BigInteger.valueOf(contractGasLimit))
                    );
                    cachedDiamond = local;
                }
            }
        }
        return local;
    }

    private String normalize(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeOrganization(String organization) {
        if (organization == null) {
            return "";
        }
        return organization.trim().toLowerCase(Locale.ROOT);
    }

    private static final class InvitePayload {
        public String inviteId;
        public String issuer;
        public String institutionWallet;
        public List<String> organizations;
        public Instant issuedAt;
        public Instant expiresAt;
    }
}
