package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.service.persistence.AntiReplayService;
import decentralabs.blockchain.util.EthereumAddressValidator;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

@ExtendWith(MockitoExtension.class)
class CheckInAuthServiceTest {

    @Mock
    private Eip712CheckInVerifier verifier;

    @Mock
    private AntiReplayService antiReplayService;

    @InjectMocks
    private CheckInAuthService service;

    @Test
    void verifyCheckInShouldReturnNormalizedResponseWhenVerificationSucceeds() {
        CheckInRequest request = validRequest();
        long timestamp = request.getTimestamp();
        String signer = EthereumAddressValidator.toChecksumAddress(request.getSigner());
        String normalizedReservationKey = normalizeBytes32(request.getReservationKey());
        String expectedPucHash = normalizeBytes32(Numeric.toHexString(Hash.sha3("puc-123".getBytes(StandardCharsets.UTF_8))));

        when(antiReplayService.isTimestampUsed(signer, timestamp * 1000)).thenReturn(false);
        when(verifier.verify(
            signer,
            normalizedReservationKey,
            expectedPucHash,
            timestamp,
            request.getSignature()
        )).thenReturn(new Eip712CheckInVerifier.VerificationResult(true, signer, null));

        CheckInResponse response = service.verifyCheckIn(request);

        assertThat(response.isValid()).isTrue();
        assertThat(response.getSigner()).isEqualTo(signer);
        assertThat(response.getReservationKey()).isEqualTo(normalizedReservationKey);
        assertThat(response.getTimestamp()).isEqualTo(timestamp);
        assertThat(response.getRecoveredAddress()).isEqualTo(signer);

        verify(antiReplayService).isTimestampUsed(signer, timestamp * 1000);
        verify(verifier).verify(signer, normalizedReservationKey, expectedPucHash, timestamp, request.getSignature());
    }

    @Test
    void verifyCheckInShouldRejectFutureTimestamp() {
        CheckInRequest request = validRequest();
        request.setTimestamp((System.currentTimeMillis() / 1000) + 60);

        assertThatThrownBy(() -> service.verifyCheckIn(request))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Timestamp in future");
    }

    @Test
    void verifyCheckInShouldRejectExpiredTimestamp() {
        CheckInRequest request = validRequest();
        request.setTimestamp((System.currentTimeMillis() / 1000) - 301);

        assertThatThrownBy(() -> service.verifyCheckIn(request))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Timestamp expired");
    }

    @Test
    void verifyCheckInShouldRejectReplayAttack() {
        CheckInRequest request = validRequest();
        String signer = EthereumAddressValidator.toChecksumAddress(request.getSigner());

        when(antiReplayService.isTimestampUsed(signer, request.getTimestamp() * 1000)).thenReturn(true);

        assertThatThrownBy(() -> service.verifyCheckIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("replay attack");
    }

    @Test
    void verifyCheckInShouldRejectInvalidVerifierResult() {
        CheckInRequest request = validRequest();
        long timestamp = request.getTimestamp();
        String signer = EthereumAddressValidator.toChecksumAddress(request.getSigner());
        String normalizedReservationKey = normalizeBytes32(request.getReservationKey());
        String expectedPucHash = normalizeBytes32(Numeric.toHexString(Hash.sha3("puc-123".getBytes(StandardCharsets.UTF_8))));

        when(antiReplayService.isTimestampUsed(signer, timestamp * 1000)).thenReturn(false);
        when(verifier.verify(
            signer,
            normalizedReservationKey,
            expectedPucHash,
            timestamp,
            request.getSignature()
        )).thenReturn(new Eip712CheckInVerifier.VerificationResult(false, null, "signature_mismatch"));

        assertThatThrownBy(() -> service.verifyCheckIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("signature_mismatch");
    }

    private CheckInRequest validRequest() {
        CheckInRequest request = new CheckInRequest();
        request.setReservationKey("0xabc123");
        request.setSigner("0x1111111111111111111111111111111111111111");
        request.setSignature("0x" + "1".repeat(130));
        request.setTimestamp((System.currentTimeMillis() / 1000) - 10);
        request.setPuc("puc-123");
        return request;
    }

    private static String normalizeBytes32(String value) {
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
