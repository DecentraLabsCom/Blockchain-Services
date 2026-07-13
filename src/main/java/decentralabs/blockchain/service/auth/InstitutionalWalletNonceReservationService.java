package decentralabs.blockchain.service.auth;

import java.math.BigInteger;
import java.util.function.Consumer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Commits nonce allocation and its owning outbox row before any RPC broadcast. */
@Service
@RequiredArgsConstructor
public class InstitutionalWalletNonceReservationService {
    private final InstitutionalCheckInOutboxService nonceStore;

    @Transactional
    public BigInteger reserve(String walletAddress, BigInteger nodePendingNonce) {
        return nonceStore.reserveNextNonce(walletAddress, nodePendingNonce);
    }

    @Transactional
    public BigInteger reserveAndPersist(
        String walletAddress,
        BigInteger nodePendingNonce,
        Consumer<BigInteger> persistNonce
    ) {
        BigInteger nonce = nonceStore.reserveNextNonce(walletAddress, nodePendingNonce);
        persistNonce.accept(nonce);
        return nonce;
    }
}
