package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.util.PucHashUtil;
import java.math.BigInteger;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

@Service
public class InstitutionalCheckInSubmissionService {
    private final InstitutionalWalletService institutionalWalletService;
    private final Eip712CheckInVerifier checkInVerifier;
    private final CheckInOnChainService checkInOnChainService;

    public InstitutionalCheckInSubmissionService(
        InstitutionalWalletService institutionalWalletService,
        Eip712CheckInVerifier checkInVerifier,
        CheckInOnChainService checkInOnChainService
    ) {
        this.institutionalWalletService = institutionalWalletService;
        this.checkInVerifier = checkInVerifier;
        this.checkInOnChainService = checkInOnChainService;
    }

    public CheckInResponse submit(String reservationKey, String pucHash) {
        return submit(reservationKey, pucHash, null);
    }

    public String signerAddress() {
        return institutionalWalletService.getInstitutionalCredentials().getAddress();
    }

    public CheckInResponse submit(String reservationKey, String pucHash, BigInteger nonce) {
        return submit(reservationKey, pucHash, nonce, 0);
    }

    public CheckInResponse submit(String reservationKey, String pucHash, BigInteger nonce, int replacementAttempt) {
        Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
        String signer = credentials.getAddress();
        String normalizedReservationKey = PucHashUtil.normalizeBytes32(reservationKey);
        String normalizedPucHash = PucHashUtil.normalizeBytes32(pucHash);
        long timestamp = System.currentTimeMillis() / 1000;

        byte[] digest = checkInVerifier.buildDigest(
            signer,
            normalizedReservationKey,
            normalizedPucHash,
            timestamp
        );
        String signature = signatureToHex(Sign.signMessage(digest, credentials.getEcKeyPair(), false));
        String txHash = nonce == null
            ? checkInOnChainService.submitSignedCheckInAsync(
                signer, normalizedReservationKey, normalizedPucHash, timestamp, signature
            )
            : checkInOnChainService.submitSignedCheckInAsync(
                signer, normalizedReservationKey, normalizedPucHash, timestamp, signature, nonce, replacementAttempt
            );

        CheckInResponse response = new CheckInResponse();
        response.setValid(true);
        response.setSigner(signer);
        response.setReservationKey(normalizedReservationKey);
        response.setTimestamp(timestamp);
        response.setTxHash(txHash);
        return response;
    }

    private String signatureToHex(Sign.SignatureData signatureData) {
        byte[] sigBytes = new byte[65];
        System.arraycopy(signatureData.getR(), 0, sigBytes, 0, 32);
        System.arraycopy(signatureData.getS(), 0, sigBytes, 32, 32);
        sigBytes[64] = signatureData.getV()[0];
        return Numeric.toHexString(sigBytes);
    }
}
