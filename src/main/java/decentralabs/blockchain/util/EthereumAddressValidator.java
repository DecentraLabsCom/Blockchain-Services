package decentralabs.blockchain.util;

import java.math.BigInteger;
import org.web3j.crypto.Keys;
import org.web3j.utils.Numeric;

/**
 * Utility class for validating Ethereum addresses
 */
public class EthereumAddressValidator {

    private static final int ADDRESS_LENGTH_WITH_PREFIX = 42; // 0x + 40 hex chars

    /**
     * Validates an Ethereum address format and optionally its checksum
     * 
     * @param address The address to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidAddress(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }

        // Check if it starts with 0x
        if (!address.startsWith("0x")) {
            return false;
        }

        // Check length
        if (address.length() != ADDRESS_LENGTH_WITH_PREFIX) {
            return false;
        }

        // Check if it's valid hex
        try {
            Numeric.toBigInt(address);
        } catch (Exception e) {
            return false;
        }

        String body = address.substring(2);
        boolean allLower = body.equals(body.toLowerCase());
        boolean allUpper = body.equals(body.toUpperCase());

        if (allLower) {
            return true; // canonical lowercase form
        }
        if (allUpper) {
            // force checksum validation to avoid ambiguous uppercase addresses
            return matchesChecksum(address);
        }

        return matchesChecksum(address);
    }

    /**
     * Validates and normalizes an Ethereum address to checksum format
     * 
     * @param address The address to normalize
     * @return The checksummed address
     * @throws IllegalArgumentException if address is invalid
     */
    public static String toChecksumAddress(String address) {
        if (!isValidAddress(address)) {
            throw new IllegalArgumentException("Invalid Ethereum address: " + address);
        }
        return Keys.toChecksumAddress(address);
    }

    /**
     * Checks if an address has mixed case (indicating it may have a checksum)
     */
    private static boolean matchesChecksum(String address) {
        try {
            String normalized = "0x" + address.substring(2).toLowerCase();
            String checksum = Keys.toChecksumAddress(normalized);
            return checksum.equals(address);
        } catch (Exception e) {
            return false;
        }
    }

    public static BigInteger parseBigInteger(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " cannot be null or empty");
        }
        try {
            return new BigInteger(value);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException(fieldName + " must be a valid number: " + value, ex);
        }
    }
}
