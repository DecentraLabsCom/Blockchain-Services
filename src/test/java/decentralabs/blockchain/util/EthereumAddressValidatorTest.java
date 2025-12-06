package decentralabs.blockchain.util;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("EthereumAddressValidator Tests")
class EthereumAddressValidatorTest {

    @Nested
    @DisplayName("isValidAddress Tests")
    class IsValidAddressTests {

        @Test
        @DisplayName("Should return false for null address")
        void shouldReturnFalseForNull() {
            assertFalse(EthereumAddressValidator.isValidAddress(null));
        }

        @Test
        @DisplayName("Should return false for empty address")
        void shouldReturnFalseForEmpty() {
            assertFalse(EthereumAddressValidator.isValidAddress(""));
        }

        @Test
        @DisplayName("Should return false for address without 0x prefix")
        void shouldReturnFalseWithoutPrefix() {
            assertFalse(EthereumAddressValidator.isValidAddress("1234567890abcdef1234567890abcdef12345678"));
        }

        @Test
        @DisplayName("Should return false for address with wrong length")
        void shouldReturnFalseForWrongLength() {
            assertFalse(EthereumAddressValidator.isValidAddress("0x1234")); // too short
            assertFalse(EthereumAddressValidator.isValidAddress("0x1234567890abcdef1234567890abcdef123456789")); // too long
        }

        @Test
        @DisplayName("Should return false for invalid hex characters")
        void shouldReturnFalseForInvalidHex() {
            assertFalse(EthereumAddressValidator.isValidAddress("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"));
        }

        @Test
        @DisplayName("Should return true for valid lowercase address")
        void shouldReturnTrueForValidLowercase() {
            assertTrue(EthereumAddressValidator.isValidAddress("0x1234567890abcdef1234567890abcdef12345678"));
        }

        @Test
        @DisplayName("Should return true for valid checksummed address")
        void shouldReturnTrueForValidChecksum() {
            // Well-known checksummed address (Vitalik's address)
            assertTrue(EthereumAddressValidator.isValidAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        }

        @Test
        @DisplayName("Should return false for invalid checksum")
        void shouldReturnFalseForInvalidChecksum() {
            // Mixed case but wrong checksum
            assertFalse(EthereumAddressValidator.isValidAddress("0xD8DA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        }

        @Test
        @DisplayName("Should return true for uppercase address with valid checksum")
        void shouldValidateUppercaseWithChecksum() {
            // All uppercase needs checksum validation
            String address = "0xD8DA6BF26964AF9D7EED9E03E53415D37AA96045";
            // This should fail checksum validation since uppercase != checksum
            assertFalse(EthereumAddressValidator.isValidAddress(address));
        }

        @Test
        @DisplayName("Should handle zero address")
        void shouldHandleZeroAddress() {
            assertTrue(EthereumAddressValidator.isValidAddress("0x0000000000000000000000000000000000000000"));
        }
    }

    @Nested
    @DisplayName("toChecksumAddress Tests")
    class ToChecksumAddressTests {

        @Test
        @DisplayName("Should convert lowercase to checksum")
        void shouldConvertToChecksum() {
            String lowercase = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
            String checksum = EthereumAddressValidator.toChecksumAddress(lowercase);
            assertEquals("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", checksum);
        }

        @Test
        @DisplayName("Should throw for invalid address")
        void shouldThrowForInvalidAddress() {
            assertThrows(IllegalArgumentException.class, 
                () -> EthereumAddressValidator.toChecksumAddress("invalid"));
        }

        @Test
        @DisplayName("Should throw for null address")
        void shouldThrowForNullAddress() {
            assertThrows(IllegalArgumentException.class, 
                () -> EthereumAddressValidator.toChecksumAddress(null));
        }

        @Test
        @DisplayName("Should preserve valid checksum address")
        void shouldPreserveValidChecksum() {
            String checksum = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
            assertEquals(checksum, EthereumAddressValidator.toChecksumAddress(checksum));
        }
    }

    @Nested
    @DisplayName("parseBigInteger Tests")
    class ParseBigIntegerTests {

        @Test
        @DisplayName("Should parse valid positive number")
        void shouldParseValidPositive() {
            BigInteger result = EthereumAddressValidator.parseBigInteger("12345", "testField");
            assertEquals(BigInteger.valueOf(12345), result);
        }

        @Test
        @DisplayName("Should parse valid negative number")
        void shouldParseValidNegative() {
            BigInteger result = EthereumAddressValidator.parseBigInteger("-12345", "testField");
            assertEquals(BigInteger.valueOf(-12345), result);
        }

        @Test
        @DisplayName("Should parse large number")
        void shouldParseLargeNumber() {
            String large = "123456789012345678901234567890";
            BigInteger result = EthereumAddressValidator.parseBigInteger(large, "testField");
            assertEquals(new BigInteger(large), result);
        }

        @Test
        @DisplayName("Should throw for null value")
        void shouldThrowForNull() {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, 
                () -> EthereumAddressValidator.parseBigInteger(null, "testField"));
            assertTrue(ex.getMessage().contains("testField"));
        }

        @Test
        @DisplayName("Should throw for blank value")
        void shouldThrowForBlank() {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, 
                () -> EthereumAddressValidator.parseBigInteger("  ", "testField"));
            assertTrue(ex.getMessage().contains("testField"));
        }

        @Test
        @DisplayName("Should throw for non-numeric value")
        void shouldThrowForNonNumeric() {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, 
                () -> EthereumAddressValidator.parseBigInteger("not-a-number", "amount"));
            assertTrue(ex.getMessage().contains("amount"));
            assertTrue(ex.getMessage().contains("valid number"));
        }

        @Test
        @DisplayName("Should parse zero")
        void shouldParseZero() {
            assertEquals(BigInteger.ZERO, EthereumAddressValidator.parseBigInteger("0", "value"));
        }
    }
}
