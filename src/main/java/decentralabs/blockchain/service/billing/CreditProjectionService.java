package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.CreditAccount;
import decentralabs.blockchain.domain.CreditLot;
import decentralabs.blockchain.domain.CreditMovement;
import decentralabs.blockchain.dto.billing.CreditLedgerSnapshot;
import decentralabs.blockchain.service.persistence.CreditAccountPersistenceService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.CreditUnitConverter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Projects on-chain credit ledger state into off-chain MySQL for querying,
 * reporting, and compliance exports.
 */
@Service
@Slf4j
public class CreditProjectionService {

    private final CreditAccountPersistenceService persistence;
    private final WalletService walletService;
    private final ConcurrentMap<String, Long> lastReconciledAt = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Object> reconciliationLocks = new ConcurrentHashMap<>();

    private static final long READ_RECONCILIATION_MIN_INTERVAL_MS = 5_000L;

    @Autowired
    public CreditProjectionService(CreditAccountPersistenceService persistence, WalletService walletService) {
        this.persistence = persistence;
        this.walletService = walletService;
    }

    /** Compatibility constructor for projection-only tests and non-chain tooling. */
    public CreditProjectionService(CreditAccountPersistenceService persistence) {
        this(persistence, null);
    }

    /**
     * Synchronize a credit account snapshot from on-chain data.
     */
    @Transactional
    public void syncAccount(String address, BigDecimal available, BigDecimal locked,
                            BigDecimal consumed, BigDecimal adjusted, BigDecimal expired) {
        CreditAccount account = CreditAccount.builder()
                .accountAddress(address.toLowerCase(Locale.ROOT))
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
                .accountAddress(address.toLowerCase(Locale.ROOT))
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
                .accountAddress(address.toLowerCase(Locale.ROOT))
                .lotIndex(lotIndex)
                .movementType(type)
                .amount(amount)
                .reservationRef(reservationRef)
                .reference(reference)
                .build());
    }

    /**
     * Reconcile the SQL projection from the Diamond's current ledger state.
     * This is idempotent: account and lot snapshots are upserted and chain
     * movements use their stable on-chain index as the source key.
     */
    @Transactional
    public CreditAccount reconcileAccount(String address) {
        String normalized = address.toLowerCase(Locale.ROOT);
        if (walletService == null) {
            return persistence.findCreditAccount(normalized)
                .orElseGet(() -> emptyAccount(normalized));
        }

        CreditLedgerSnapshot snapshot = walletService.getCreditLedgerSnapshot(normalized);
        CreditAccount previous = persistence.findCreditAccount(normalized).orElse(null);
        CreditAccount account = CreditAccount.builder()
            .accountAddress(normalized)
            .available(toCredits(snapshot.available()))
            .locked(toCredits(snapshot.locked()))
            // These cumulative fields pre-date the on-chain snapshot API.
            // Preserve an existing value until a dedicated historical
            // accounting source is available instead of resetting it to zero.
            .consumed(previous == null ? BigDecimal.ZERO : valueOrZero(previous.getConsumed()))
            .adjusted(previous == null ? BigDecimal.ZERO : valueOrZero(previous.getAdjusted()))
            .expired(previous == null ? BigDecimal.ZERO : valueOrZero(previous.getExpired()))
            .build();
        persistence.upsertCreditAccount(account);

        Instant now = Instant.now();
        for (CreditLedgerSnapshot.Lot lot : snapshot.lots()) {
            Instant expiresAt = toInstant(lot.expiresAtEpochSeconds());
            boolean expired = lot.expired()
                || (expiresAt != null && !expiresAt.isAfter(now));
            syncLot(
                normalized,
                lot.index(),
                parseFundingOrderId(lot.fundingOrderReference()),
                toEur(lot.eurGrossAmountCents()),
                toCredits(lot.creditAmount()),
                toCredits(lot.remaining()),
                toInstant(lot.issuedAtEpochSeconds()),
                expiresAt,
                expired
            );
        }

        for (CreditLedgerSnapshot.Movement movement : snapshot.movements()) {
            persistence.upsertCreditMovement(toDomainMovement(normalized, movement));
        }
        lastReconciledAt.put(normalized, System.currentTimeMillis());
        return account;
    }

    public Optional<CreditAccount> getAccount(String address) {
        reconcileForRead(address);
        return persistence.findCreditAccount(address.toLowerCase(Locale.ROOT));
    }

    public List<CreditLot> getLots(String address) {
        reconcileForRead(address);
        return persistence.findCreditLots(address.toLowerCase(Locale.ROOT));
    }

    public List<CreditLot> getExpiringLots(Instant before) {
        return persistence.findExpiringLots(before);
    }

    public List<CreditMovement> getMovements(String address, int limit) {
        reconcileForRead(address);
        return persistence.findMovements(address.toLowerCase(Locale.ROOT), limit);
    }

    private void reconcileForRead(String address) {
        if (walletService == null) return;
        String normalized = address.toLowerCase(Locale.ROOT);
        long now = System.currentTimeMillis();
        Long last = lastReconciledAt.get(normalized);
        if (last != null && now - last < READ_RECONCILIATION_MIN_INTERVAL_MS) return;
        Object lock = reconciliationLocks.computeIfAbsent(normalized, ignored -> new Object());
        synchronized (lock) {
            long lockedNow = System.currentTimeMillis();
            Long lockedLast = lastReconciledAt.get(normalized);
            if (lockedLast != null && lockedNow - lockedLast < READ_RECONCILIATION_MIN_INTERVAL_MS) return;
            try {
                reconcileAccount(normalized);
            } catch (RuntimeException ex) {
                // The SQL projection remains a safe stale fallback when the RPC
                // is temporarily unavailable. Never fabricate a zero balance.
                log.warn("Credit projection reconciliation unavailable for {}", maskAddress(normalized));
            }
        }
    }

    private CreditMovement toDomainMovement(String address, CreditLedgerSnapshot.Movement movement) {
        CreditMovement.Type type = CreditMovement.Type.valueOf(movement.type());
        String reference = normalizeReference(movement.reference());
        boolean reservationMovement = type == CreditMovement.Type.LOCK
            || type == CreditMovement.Type.CAPTURE
            || type == CreditMovement.Type.RELEASE
            || type == CreditMovement.Type.CANCEL;
        return CreditMovement.builder()
            .accountAddress(address)
            .movementType(type)
            .amount(toCredits(movement.amount()))
            .reservationRef(reservationMovement ? reference : null)
            .reference(reservationMovement ? null : reference)
            .sourceKey("onchain:" + movement.index())
            .createdAt(toInstant(movement.timestampEpochSeconds()))
            .build();
    }

    private CreditAccount emptyAccount(String address) {
        return CreditAccount.builder()
            .accountAddress(address)
            .available(BigDecimal.ZERO)
            .locked(BigDecimal.ZERO)
            .consumed(BigDecimal.ZERO)
            .adjusted(BigDecimal.ZERO)
            .expired(BigDecimal.ZERO)
            .build();
    }

    private BigDecimal toCredits(BigInteger raw) {
        return new BigDecimal(raw == null ? BigInteger.ZERO : raw)
            .movePointLeft(CreditUnitConverter.CREDIT_DECIMALS);
    }

    private BigDecimal toEur(BigInteger cents) {
        return new BigDecimal(cents == null ? BigInteger.ZERO : cents).movePointLeft(2);
    }

    private BigDecimal valueOrZero(BigDecimal value) {
        return value == null ? BigDecimal.ZERO : value;
    }

    private Instant toInstant(BigInteger epochSeconds) {
        if (epochSeconds == null || epochSeconds.signum() <= 0) return null;
        return Instant.ofEpochSecond(epochSeconds.longValueExact());
    }

    private Long parseFundingOrderId(String reference) {
        // Funding order references are bytes32 hashes on-chain. Preserve only
        // legacy numeric values that can safely fit the SQL compatibility
        // column; arbitrary references remain available in the raw chain data.
        if (reference == null || reference.isBlank()) return null;
        try {
            BigInteger value = new BigInteger(reference.replaceFirst("^0x", ""), 16);
            return value.signum() == 0 ? null : value.longValueExact();
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private String normalizeReference(String reference) {
        if (reference == null || reference.isBlank() || reference.matches("0x0+")) return null;
        return reference;
    }

    private String maskAddress(String address) {
        if (address == null || address.length() < 10) return "address";
        return address.substring(0, 6) + "…" + address.substring(address.length() - 4);
    }
}
