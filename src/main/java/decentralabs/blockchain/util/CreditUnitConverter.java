package decentralabs.blockchain.util;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;

/**
 * Canonical credit-unit conversions shared across billing and admin surfaces.
 *
 * Commercial policy:
 * - 10 credits = 1 EUR
 * - service credits use 5 on-chain decimal places
 */
public final class CreditUnitConverter {

    public static final int CREDIT_DECIMALS = 5;
    public static final BigDecimal CREDITS_PER_EUR = BigDecimal.TEN;
    public static final BigDecimal RAW_PER_CREDIT = BigDecimal.valueOf(100_000L);
    public static final BigDecimal RAW_PER_EUR = RAW_PER_CREDIT.multiply(CREDITS_PER_EUR);
    public static final String DEFAULT_USER_LIMIT_RAW = "1000000"; // 10 credits

    private CreditUnitConverter() {
    }

    public static BigDecimal normalizeEur(BigDecimal eurAmount) {
        if (eurAmount == null) {
            return null;
        }
        return eurAmount.setScale(2, RoundingMode.HALF_UP);
    }

    public static BigDecimal creditsFromEur(BigDecimal eurAmount) {
        BigDecimal normalized = normalizeEur(eurAmount);
        if (normalized == null) {
            return null;
        }
        return normalized.multiply(CREDITS_PER_EUR).setScale(CREDIT_DECIMALS, RoundingMode.UNNECESSARY);
    }

    public static String formatRawCredits(BigInteger rawValue) {
        if (rawValue == null) {
            return "0";
        }
        return new BigDecimal(rawValue)
            .movePointLeft(CREDIT_DECIMALS)
            .stripTrailingZeros()
            .toPlainString();
    }
}
