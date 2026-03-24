package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.CreditAccount;
import decentralabs.blockchain.domain.CreditLot;
import decentralabs.blockchain.domain.CreditMovement;
import decentralabs.blockchain.service.persistence.CreditAccountPersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Projects on-chain credit ledger state into off-chain MySQL for querying,
 * reporting, and compliance exports.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CreditProjectionService {

    private final CreditAccountPersistenceService persistence;

    /**
     * Synchronize a credit account snapshot from on-chain data.
     */
    @Transactional
    public void syncAccount(String address, BigDecimal available, BigDecimal locked,
                            BigDecimal consumed, BigDecimal adjusted, BigDecimal expired) {
        CreditAccount account = CreditAccount.builder()
                .accountAddress(address.toLowerCase())
                .available(available)
                .locked(locked)
                .consumed(consumed)
                .adjusted(adjusted)
                .expired(expired)
                .build();
        persistence.upsertCreditAccount(account);
    }

    /**
     * Synchronize a credit lot snapshot from on-chain data.
     */
    @Transactional
    public void syncLot(String address, int lotIndex, Long fundingOrderId,
                        BigDecimal eurGrossAmount, BigDecimal creditAmount,
                        BigDecimal remaining, Instant issuedAt, Instant expiresAt, boolean expired) {
        CreditLot lot = CreditLot.builder()
                .accountAddress(address.toLowerCase())
                .lotIndex(lotIndex)
                .fundingOrderId(fundingOrderId)
                .eurGrossAmount(eurGrossAmount)
                .creditAmount(creditAmount)
                .remaining(remaining)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .expired(expired)
                .build();
        persistence.upsertCreditLot(lot);
    }

    /**
     * Record a credit movement for audit trail.
     */
    @Transactional
    public void recordMovement(String address, Integer lotIndex, CreditMovement.Type type,
                               BigDecimal amount, String reservationRef, String reference) {
        persistence.recordMovement(CreditMovement.builder()
                .accountAddress(address.toLowerCase())
                .lotIndex(lotIndex)
                .movementType(type)
                .amount(amount)
                .reservationRef(reservationRef)
                .reference(reference)
                .build());
    }

    public Optional<CreditAccount> getAccount(String address) {
        return persistence.findCreditAccount(address.toLowerCase());
    }

    public List<CreditLot> getLots(String address) {
        return persistence.findCreditLots(address.toLowerCase());
    }

    public List<CreditLot> getExpiringLots(Instant before) {
        return persistence.findExpiringLots(before);
    }

    public List<CreditMovement> getMovements(String address, int limit) {
        return persistence.findMovements(address.toLowerCase(), limit);
    }
}
