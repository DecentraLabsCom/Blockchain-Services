package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
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
    private static final BigInteger STATUS_ACCESS_AUTHORIZED = BigInteger.valueOf(2);

    private static final class MarketplaceIdentityClaims {
        private final String userId;
        private final String puc;
        private final String institutionalProviderWallet;

        MarketplaceIdentityClaims(String userId, String puc, String institutionalProviderWallet) {
            this.userId = userId;
            this.puc = puc;
            this.institutionalProviderWallet = institutionalProviderWallet;
        }
    }

    private final SamlValidationService samlValidationService;
    private final MarketplaceEndpointAuthService marketplaceEndpointAuthService;
    private final BlockchainBookingService bookingService;
    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;
    private final Eip712CheckInVerifier checkInVerifier;
    private final CheckInOnChainService checkInOnChainService;
    private final InstitutionalCheckInDirectoryService directoryService;
    private final RemoteInstitutionalCheckInClient remoteCheckInClient;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${institutional.checkin.delegation.enabled:true}")
    private boolean delegationEnabled;

    public CheckInResponse checkIn(InstitutionalCheckInRequest request) {
        validateRequest(request);

        SamlAssertionAttributes saml = validateSaml(request.getSamlAssertion());
        MarketplaceIdentityClaims marketplaceIdentity = validateMarketplaceToken(request, saml);

        String tokenIdentity = PucNormalizer.normalize(firstNonBlank(marketplaceIdentity.puc, marketplaceIdentity.userId));
        String samlIdentity = PucNormalizer.normalize(saml.userid());
        String puc = firstNonBlank(tokenIdentity, samlIdentity);
        if (puc == null || puc.isBlank()) {
            throw new IllegalArgumentException("Missing institutional user identifier");
        }

        String requestPuc = PucNormalizer.normalize(request.getPuc());
        if (requestPuc != null && !requestPuc.isBlank() && !requestPuc.equals(puc)) {
            throw new SecurityException("Request puc does not match authenticated user");
        }

        String institutionOrganization = resolveInstitutionOrganization(saml);
        String institutionWallet = resolveInstitutionWallet(request, institutionOrganization);
        if (institutionWallet == null || institutionWallet.isBlank() || ZERO_ADDRESS.equalsIgnoreCase(institutionWallet)) {
            throw new IllegalArgumentException("Institution wallet could not be resolved");
        }

        String claimedInstitutionWallet = normalizeAddress(marketplaceIdentity.institutionalProviderWallet);
        if (claimedInstitutionWallet != null && !claimedInstitutionWallet.equalsIgnoreCase(institutionWallet)) {
            throw new SecurityException("Marketplace token institutionalProviderWallet mismatch");
        }

        Map<String, Object> bookingInfo = bookingService.getCheckInBookingInfo(
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

        if (isAccessAuthorizedStatus(bookingInfo.get("reservationStatus"))) {
            CheckInResponse response = new CheckInResponse();
            response.setValid(true);
            response.setReservationKey(reservationKey);
            response.setReason("Access already authorized");
            response.setTimestamp(System.currentTimeMillis() / 1000);
            return response;
        }

        String configuredSigner = normalizeAddress(institutionalWalletService.getInstitutionalWalletAddress());
        if (!directoryService.isAuthorizedCheckInSigner(institutionWallet, configuredSigner)) {
            return delegateToInstitutionBackend(request, institutionOrganization, institutionWallet);
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

    private MarketplaceIdentityClaims validateMarketplaceToken(InstitutionalCheckInRequest request, SamlAssertionAttributes saml) {
        try {
            String marketplaceToken = request.getMarketplaceToken();
            Map<String, Object> claims = marketplaceEndpointAuthService.enforceToken(marketplaceToken, null);
            String claimUser = firstClaim(claims, "userid", "sub", "uid");
            // affiliation is validated above but not retained in the return object
            String claimAffiliation = firstClaim(claims, "affiliation", "schacHomeOrganization");

            if (claimUser == null || claimUser.isBlank() || claimAffiliation == null || claimAffiliation.isBlank()) {
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
            if (saml.affiliation() != null && !saml.affiliation().isBlank() && !claimAffiliation.equals(saml.affiliation())) {
                throw new SecurityException("Marketplace token affiliation mismatch");
            }
            enforceRequiredClaim(claims, "purpose", "lab_access");
            enforceBoundClaim(claims, "reservationKey", request.getReservationKey());
            enforceBoundClaim(claims, "labId", request.getLabId());
            enforceRequiredSamlAssertionHash(claims, request.getSamlAssertion());

            String claimPuc = firstClaim(claims, "puc");
            String claimInstitutionalProviderWallet = firstClaim(claims, "institutionalProviderWallet");
            return new MarketplaceIdentityClaims(
                claimUser,
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

    private String resolveInstitutionWallet(InstitutionalCheckInRequest request, String organization) {
        String explicit = normalizeAddress(request.getInstitutionalProviderWallet());
        if (explicit != null && !explicit.isBlank()) {
            return explicit;
        }

        return resolveInstitutionAddress(organization);
    }

    private String resolveInstitutionOrganization(SamlAssertionAttributes saml) {
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

        return normalizeOrganization(org);
    }

    private CheckInResponse delegateToInstitutionBackend(
        InstitutionalCheckInRequest request,
        String organization,
        String institutionWallet
    ) {
        if (!delegationEnabled) {
            throw new IllegalStateException("Local wallet is not authorized for institution check-in");
        }
        String backendUrl = directoryService.resolveOrganizationBackendUrl(organization);
        if (backendUrl == null || backendUrl.isBlank()) {
            throw new IllegalStateException("No institutional backend registered for organization " + organization);
        }
        request.setInstitutionalProviderWallet(institutionWallet);
        log.info("Delegating institutional check-in for organization {} to registered backend", organization);
        return remoteCheckInClient.submit(backendUrl, request);
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

    private boolean isAccessAuthorizedStatus(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof BigInteger status) {
            return STATUS_ACCESS_AUTHORIZED.equals(status);
        }
        if (value instanceof Number status) {
            return status.longValue() == STATUS_ACCESS_AUTHORIZED.longValue();
        }
        try {
            return STATUS_ACCESS_AUTHORIZED.equals(new BigInteger(value.toString()));
        } catch (RuntimeException ex) {
            log.debug("Unable to parse reservation status '{}'", value, ex);
            return false;
        }
    }

    private void enforceRequiredSamlAssertionHash(Map<String, Object> claims, String samlAssertion) {
        String expectedHash = firstClaim(claims, "samlAssertionHash");
        if (expectedHash == null || expectedHash.isBlank()) {
            throw new SecurityException("Marketplace token samlAssertionHash is required");
        }
        String actualHash = Numeric.toHexString(Hash.sha3(samlAssertion.getBytes(StandardCharsets.UTF_8)));
        if (!expectedHash.equalsIgnoreCase(actualHash)) {
            throw new SecurityException("Marketplace token samlAssertionHash mismatch");
        }
    }

    private void enforceBoundClaim(Map<String, Object> claims, String claim, String expected) {
        if (expected == null || expected.isBlank()) {
            return;
        }
        enforceRequiredClaim(claims, claim, expected);
    }

    private void enforceRequiredClaim(Map<String, Object> claims, String claim, String expected) {
        String value = firstClaim(claims, claim);
        if (value == null || value.isBlank()) {
            throw new SecurityException("Marketplace token " + claim + " is required");
        }
        if (!value.equals(expected)) {
            throw new SecurityException("Marketplace token " + claim + " mismatch");
        }
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
