package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.service.persistence.AntiReplayService;
import decentralabs.blockchain.util.EthereumAddressValidator;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

@Service
@RequiredArgsConstructor
public class CheckInAuthService {
    private static final long MAX_CHECKIN_DELAY_SEC = 5 * 60;

    private final Eip712CheckInVerifier verifier;
    private final AntiReplayService antiReplayService;

    public CheckInResponse verifyCheckIn(CheckInRequest request) {
        validateRequest(request);

        String signer = EthereumAddressValidator.toChecksumAddress(request.getSigner());
        String reservationKey = normalizeBytes32(request.getReservationKey());
        String pucHash = computePucHash(request.getPuc());
        long timestamp = request.getTimestamp();

        long nowSec = System.currentTimeMillis() / 1000;
        if (timestamp > nowSec) {
            throw new IllegalArgumentException("Timestamp in future");
        }
        if ((nowSec - timestamp) > MAX_CHECKIN_DELAY_SEC) {
            throw new IllegalArgumentException("Timestamp expired");
        }

        if (antiReplayService.isTimestampUsed(signer, timestamp * 1000)) {
            throw new SecurityException("Timestamp already used (replay attack detected)");
        }

        Eip712CheckInVerifier.VerificationResult result = verifier.verify(
            signer,
            reservationKey,
            pucHash,
            timestamp,
            request.getSignature()
        );

        if (!result.valid()) {
            throw new SecurityException(result.error());
        }

        CheckInResponse response = new CheckInResponse();
        response.setValid(true);
        response.setReservationKey(reservationKey);
        response.setSigner(signer);
        response.setTimestamp(timestamp);
        response.setRecoveredAddress(result.recoveredAddress());
        return response;
    }

    private void validateRequest(CheckInRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Missing request");
        }
        if (request.getReservationKey() == null || request.getReservationKey().isBlank()) {
            throw new IllegalArgumentException("Missing reservationKey");
        }
        if (request.getSigner() == null || request.getSigner().isBlank()) {
            throw new IllegalArgumentException("Missing signer");
        }
        if (!EthereumAddressValidator.isValidAddress(request.getSigner())) {
            throw new IllegalArgumentException("Invalid signer address");
        }
        if (request.getSignature() == null || request.getSignature().isBlank()) {
            throw new IllegalArgumentException("Missing signature");
        }
        if (request.getTimestamp() == null || request.getTimestamp() <= 0) {
            throw new IllegalArgumentException("Missing timestamp");
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
}
