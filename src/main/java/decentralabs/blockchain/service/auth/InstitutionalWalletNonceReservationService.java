package decentralabs.blockchain.service.auth;

import java.math.BigInteger;
import java.util.function.BiConsumer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Commits nonce allocation and its owning outbox row before any RPC broadcast. */
@Service
@RequiredArgsConstructor
public class InstitutionalWalletNonceReservationService {
    private final InstitutionalCheckInOutboxService nonceStore;

    @Transactional
    public BigInteger reserveAndPersist(
        String walletAddress,
        BigInteger chainId,
        BigInteger nodePendingNonce,
        BiConsumer<BigInteger, BigInteger> persistNonce
    ) {
        BigInteger nonce = nonceStore.reserveNextNonce(chainId, walletAddress, nodePendingNonce);
        persistNonce.accept(chainId, nonce);
        return nonce;
    }

    @Transactional
    public BigInteger reserve(String walletAddress, BigInteger chainId, BigInteger nodePendingNonce) {
        return nonceStore.reserveNextNonce(chainId, walletAddress, nodePendingNonce);
    }
}
