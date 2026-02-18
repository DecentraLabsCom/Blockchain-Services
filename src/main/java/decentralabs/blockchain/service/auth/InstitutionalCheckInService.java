package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.utils.Numeric;
import decentralabs.blockchain.util.PucNormalizer;

@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalCheckInService {
    private static final String ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

    private final SamlValidationService samlValidationService;
    private final MarketplaceKeyService marketplaceKeyService;
    private final BlockchainBookingService bookingService;
    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;
    private final Eip712CheckInVerifier checkInVerifier;
    private final CheckInOnChainService checkInOnChainService;

    @Value("${contract.address}")
    private String contractAddress;

    public CheckInResponse checkIn(InstitutionalCheckInRequest request) {
        validateRequest(request);

        SamlAssertionAttributes saml = validateSaml(request.getSamlAssertion());

        if (request.getMarketplaceToken() != null && !request.getMarketplaceToken().isBlank()) {
            validateMarketplaceToken(request.getMarketplaceToken(), saml);
        }

        String puc = PucNormalizer.normalize(firstNonBlank(request.getPuc(), saml.userid()));
        if (puc == null || puc.isBlank()) {
            throw new IllegalArgumentException("Missing institutional user identifier");
        }

        String institutionWallet = resolveInstitutionWallet(request, saml);
        if (institutionWallet == null || institutionWallet.isBlank() || ZERO_ADDRESS.equalsIgnoreCase(institutionWallet)) {
            throw new IllegalArgumentException("Institution wallet could not be resolved");
        }

        Map<String, Object> bookingInfo = bookingService.getBookingInfo(
            institutionWallet,
            request.getReservationKey(),
            request.getLabId(),
            puc
        );

        String reservationKey = bookingInfo.get("reservationKey") != null
            ? bookingInfo.get("reservationKey").toString()
            : null;
        if (reservationKey == null || reservationKey.isBlank()) {
            throw new IllegalStateException("Reservation key could not be resolved");
        }

        Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
        String signer = credentials.getAddress();
        long timestamp = System.currentTimeMillis() / 1000;

        String pucHash = computePucHash(puc);
        byte[] digest = checkInVerifier.buildDigest(signer, normalizeBytes32(reservationKey), pucHash, timestamp);
        Sign.SignatureData signatureData = Sign.signMessage(digest, credentials.getEcKeyPair(), false);
        String signatureHex = signatureToHex(signatureData);

        CheckInRequest checkInRequest = new CheckInRequest();
        checkInRequest.setReservationKey(reservationKey);
        checkInRequest.setSigner(signer);
        checkInRequest.setSignature(signatureHex);
        checkInRequest.setTimestamp(timestamp);
        checkInRequest.setPuc(puc);

        return checkInOnChainService.verifyAndSubmit(checkInRequest);
    }

    private void validateRequest(InstitutionalCheckInRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Missing request");
        }
        if (request.getSamlAssertion() == null || request.getSamlAssertion().isBlank()) {
            throw new IllegalArgumentException("Missing samlAssertion");
        }
        boolean hasReservationKey = request.getReservationKey() != null && !request.getReservationKey().isBlank();
        boolean hasLabId = request.getLabId() != null && !request.getLabId().isBlank();
        if (!hasReservationKey && !hasLabId) {
            throw new IllegalArgumentException("Missing reservationKey or labId");
        }
    }

    private SamlAssertionAttributes validateSaml(String samlAssertion) {
        try {
            return samlValidationService.validateSamlAssertionDetailed(samlAssertion);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid samlAssertion: " + e.getMessage(), e);
        }
    }

    private void validateMarketplaceToken(String marketplaceToken, SamlAssertionAttributes saml) {
        try {
            PublicKey marketplacePublicKey = marketplaceKeyService.getPublicKey(false);
            Jws<Claims> jws = Jwts.parser()
                .verifyWith(marketplacePublicKey)
                .build()
                .parseSignedClaims(marketplaceToken);

            Map<String, Object> claims = jws.getPayload();
            String claimUser = firstClaim(claims, "userid", "sub", "uid");
            String claimAffiliation = firstClaim(claims, "affiliation", "schacHomeOrganization");

            if (claimUser == null || claimAffiliation == null) {
                throw new IllegalArgumentException("Marketplace token missing required claims");
            }
            String normalizedClaimUser = PucNormalizer.normalize(claimUser);
            String normalizedSamlUser = PucNormalizer.normalize(saml.userid());
            if (normalizedSamlUser != null
                && !normalizedSamlUser.isBlank()
                && normalizedClaimUser != null
                && !normalizedClaimUser.equals(normalizedSamlUser)) {
                throw new SecurityException("Marketplace token userid mismatch");
            }
            if (saml.affiliation() != null && !claimAffiliation.equals(saml.affiliation())) {
                throw new SecurityException("Marketplace token affiliation mismatch");
            }
        } catch (SecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid marketplace token: " + ex.getMessage(), ex);
        }
    }

    private String resolveInstitutionWallet(InstitutionalCheckInRequest request, SamlAssertionAttributes saml) {
        String explicit = normalizeAddress(request.getInstitutionalProviderWallet());
        if (explicit != null && !explicit.isBlank()) {
            return explicit;
        }

        String org = null;
        if (saml.schacHomeOrganizations() != null && !saml.schacHomeOrganizations().isEmpty()) {
            org = saml.schacHomeOrganizations().get(0);
        }
        if (org == null || org.isBlank()) {
            org = saml.affiliation();
        }

        if (org == null || org.isBlank()) {
            throw new IllegalArgumentException("Missing institution organization");
        }

        return resolveInstitutionAddress(org);
    }

    private String resolveInstitutionAddress(String organization) {
        String normalized = normalizeOrganization(organization);
        if (normalized.isBlank()) {
            return null;
        }
        try {
            Web3j web3j = walletService.getWeb3jInstance();
            Function function = new Function(
                "resolveSchacHomeOrganization",
                List.of(new Utf8String(normalized)),
                List.of(new TypeReference<Address>() { })
            );
            String encoded = FunctionEncoder.encode(function);
            var response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encoded),
                DefaultBlockParameterName.LATEST
            ).send();
            if (response == null || response.hasError()) {
                return null;
            }
            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (decoded.isEmpty()) {
                return null;
            }
            Object value = decoded.get(0).getValue();
            return value != null ? value.toString() : null;
        } catch (Exception ex) {
            log.warn("Unable to resolve institution wallet: {}", ex.getMessage());
            return null;
        }
    }

    private String computePucHash(String puc) {
        if (puc == null || puc.isBlank()) {
            return "0x" + "0".repeat(64);
        }
        byte[] hash = Hash.sha3(puc.getBytes(StandardCharsets.UTF_8));
        return normalizeBytes32(Numeric.toHexString(hash));
    }

    private String normalizeBytes32(String value) {
        String clean = Numeric.cleanHexPrefix(value == null ? "" : value);
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }

    private String signatureToHex(Sign.SignatureData signatureData) {
        byte[] sigBytes = new byte[65];
        System.arraycopy(signatureData.getR(), 0, sigBytes, 0, 32);
        System.arraycopy(signatureData.getS(), 0, sigBytes, 32, 32);
        byte[] v = signatureData.getV();
        sigBytes[64] = v[0];
        return Numeric.toHexString(sigBytes);
    }

    private String normalizeOrganization(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeAddress(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String firstClaim(Map<String, Object> claims, String... keys) {
        for (String key : keys) {
            Object value = claims.get(key);
            if (value != null) {
                return value.toString();
            }
        }
        return null;
    }

    private String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        if (second != null && !second.isBlank()) {
            return second;
        }
        return null;
    }
}
