package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.identity.IdentityEvidenceDTO;
import decentralabs.blockchain.dto.identity.NormalizedClaims;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
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

    private static final class MarketplaceIdentityClaims {
        private final String userId;
        private final String affiliation;
        private final String puc;
        private final String institutionalProviderWallet;

        MarketplaceIdentityClaims(String userId, String affiliation, String puc, String institutionalProviderWallet) {
            this.userId = userId;
            this.affiliation = affiliation;
            this.puc = puc;
            this.institutionalProviderWallet = institutionalProviderWallet;
        }
    }

    private record ResolvedIdentityContext(
        String userId,
        String affiliation,
        String puc,
        String institutionalProviderWallet,
        SamlAssertionAttributes samlAttributes
    ) {}

    private final SamlValidationService samlValidationService;
    private final MarketplaceEndpointAuthService marketplaceEndpointAuthService;
    private final BlockchainBookingService bookingService;
    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;
    private final Eip712CheckInVerifier checkInVerifier;
    private final CheckInOnChainService checkInOnChainService;

    @Value("${contract.address}")
    private String contractAddress;

    public CheckInResponse checkIn(InstitutionalCheckInRequest request) {
        validateRequest(request);

        ResolvedIdentityContext identity = resolveIdentityContext(request);
        MarketplaceIdentityClaims marketplaceIdentity = validateMarketplaceToken(request.getMarketplaceToken(), identity);

        String tokenIdentity = PucNormalizer.normalize(firstNonBlank(marketplaceIdentity.puc, marketplaceIdentity.userId));
        String sourceIdentity = PucNormalizer.normalize(firstNonBlank(identity.puc, identity.userId));
        String puc = firstNonBlank(tokenIdentity, sourceIdentity);
        if (puc == null || puc.isBlank()) {
            throw new IllegalArgumentException("Missing institutional user identifier");
        }

        String requestPuc = PucNormalizer.normalize(request.getPuc());
        if (requestPuc != null && !requestPuc.isBlank() && !requestPuc.equals(puc)) {
            throw new SecurityException("Request puc does not match authenticated user");
        }

        String institutionWallet = resolveInstitutionWallet(request, identity);
        if (institutionWallet == null || institutionWallet.isBlank() || ZERO_ADDRESS.equalsIgnoreCase(institutionWallet)) {
            throw new IllegalArgumentException("Institution wallet could not be resolved");
        }

        String claimedInstitutionWallet = normalizeAddress(marketplaceIdentity.institutionalProviderWallet);
        if (claimedInstitutionWallet != null && !claimedInstitutionWallet.equalsIgnoreCase(institutionWallet)) {
            throw new SecurityException("Marketplace token institutionalProviderWallet mismatch");
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
        boolean hasSaml = request.getSamlAssertion() != null && !request.getSamlAssertion().isBlank();
        boolean hasIdentityEvidence = request.getIdentityEvidence() != null || request.getNormalizedClaims() != null;
        if (!hasSaml && !hasIdentityEvidence) {
            throw new IllegalArgumentException("Missing identity evidence");
        }
        if (request.getMarketplaceToken() == null || request.getMarketplaceToken().isBlank()) {
            throw new IllegalArgumentException("Missing marketplaceToken");
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

    private MarketplaceIdentityClaims validateMarketplaceToken(String marketplaceToken, ResolvedIdentityContext identity) {
        try {
            Map<String, Object> claims = marketplaceEndpointAuthService.enforceToken(marketplaceToken, null);
            String claimUser = firstClaim(claims, "userid", "sub", "uid");
            String claimAffiliation = firstClaim(claims, "affiliation", "schacHomeOrganization");

            if (claimUser == null || claimUser.isBlank() || claimAffiliation == null || claimAffiliation.isBlank()) {
                throw new IllegalArgumentException("Marketplace token missing required claims");
            }
            String normalizedClaimUser = PucNormalizer.normalize(claimUser);
            String normalizedIdentityUser = PucNormalizer.normalize(identity.userId());
            if (normalizedIdentityUser != null
                && !normalizedIdentityUser.isBlank()
                && normalizedClaimUser != null
                && !normalizedClaimUser.equals(normalizedIdentityUser)) {
                throw new SecurityException("Marketplace token userid mismatch");
            }
            if (identity.affiliation() != null && !identity.affiliation().isBlank() && !claimAffiliation.equals(identity.affiliation())) {
                throw new SecurityException("Marketplace token affiliation mismatch");
            }

            String claimPuc = firstClaim(claims, "puc");
            String claimInstitutionalProviderWallet = firstClaim(claims, "institutionalProviderWallet");
            return new MarketplaceIdentityClaims(
                claimUser,
                claimAffiliation,
                claimPuc,
                claimInstitutionalProviderWallet
            );
        } catch (ResponseStatusException ex) {
            if (ex.getStatusCode().equals(HttpStatus.UNAUTHORIZED) || ex.getStatusCode().equals(HttpStatus.FORBIDDEN)) {
                throw new SecurityException("Invalid marketplace token: " + ex.getReason(), ex);
            }
            throw new IllegalArgumentException("Invalid marketplace token: " + ex.getReason(), ex);
        } catch (SecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid marketplace token: " + ex.getMessage(), ex);
        }
    }

    private String resolveInstitutionWallet(InstitutionalCheckInRequest request, ResolvedIdentityContext identity) {
        String explicit = normalizeAddress(request.getInstitutionalProviderWallet());
        if (explicit != null && !explicit.isBlank()) {
            return explicit;
        }

        String org = identity.affiliation();
        if ((org == null || org.isBlank()) && identity.samlAttributes() != null) {
            SamlAssertionAttributes saml = identity.samlAttributes();
            if (saml.schacHomeOrganizations() != null && !saml.schacHomeOrganizations().isEmpty()) {
                org = saml.schacHomeOrganizations().get(0);
            }
            if (org == null || org.isBlank()) {
                org = saml.affiliation();
            }
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

    private ResolvedIdentityContext resolveIdentityContext(InstitutionalCheckInRequest request) {
        IdentityEvidenceDTO identityEvidence = request.getIdentityEvidence();
        NormalizedClaims normalizedClaims = request.getNormalizedClaims();
        if (normalizedClaims == null && identityEvidence != null) {
            normalizedClaims = identityEvidence.normalizedClaims();
        }

        String evidenceUserId = normalizedClaims != null ? normalizedClaims.stableUserId() : null;
        String evidenceAffiliation = normalizedClaims != null ? normalizedClaims.institutionId() : null;
        String evidencePuc = normalizedClaims != null ? normalizedClaims.puc() : null;

        if (identityEvidence != null || normalizedClaims != null) {
            return new ResolvedIdentityContext(
                firstNonBlank(evidenceUserId, request.getPuc()),
                evidenceAffiliation,
                firstNonBlank(evidencePuc, request.getPuc(), evidenceUserId),
                request.getInstitutionalProviderWallet(),
                null
            );
        }

        SamlAssertionAttributes saml = validateSaml(request.getSamlAssertion());
        return new ResolvedIdentityContext(
            saml.userid(),
            saml.affiliation(),
            request.getPuc(),
            request.getInstitutionalProviderWallet(),
            saml
        );
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

    private String firstNonBlank(String first, String second, String third) {
        String value = firstNonBlank(first, second);
        if (value != null) {
            return value;
        }
        if (third != null && !third.isBlank()) {
            return third;
        }
        return null;
    }
}
