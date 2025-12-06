package decentralabs.blockchain.util;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("LogSanitizer Tests")
class LogSanitizerTest {

    @Nested
    @DisplayName("sanitize Tests")
    class SanitizeTests {

        @Test
        @DisplayName("Should return empty string for null input")
        void shouldReturnEmptyForNull() {
            assertEquals("", LogSanitizer.sanitize(null));
        }

        @Test
        @DisplayName("Should return same string when no control characters")
        void shouldReturnSameWhenNoControlChars() {
            String input = "Hello World 123";
            assertEquals(input, LogSanitizer.sanitize(input));
        }

        @Test
        @DisplayName("Should replace newline with underscore")
        void shouldReplaceNewline() {
            assertEquals("line1_line2", LogSanitizer.sanitize("line1\nline2"));
        }

        @Test
        @DisplayName("Should replace carriage return with underscore")
        void shouldReplaceCarriageReturn() {
            assertEquals("line1_line2", LogSanitizer.sanitize("line1\rline2"));
        }

        @Test
        @DisplayName("Should replace tab with underscore")
        void shouldReplaceTab() {
            assertEquals("col1_col2", LogSanitizer.sanitize("col1\tcol2"));
        }

        @Test
        @DisplayName("Should replace multiple control chars with single underscore")
        void shouldReplaceMultipleControlChars() {
            assertEquals("a_b_c", LogSanitizer.sanitize("a\n\r\tb\t\n\rc"));
        }

        @Test
        @DisplayName("Should handle log injection attempt")
        void shouldPreventLogInjection() {
            // Attacker tries to inject fake log line
            String malicious = "normal data\n[ERROR] Fake error message";
            String sanitized = LogSanitizer.sanitize(malicious);
            assertFalse(sanitized.contains("\n"));
            assertTrue(sanitized.contains("_"));
        }

        @Test
        @DisplayName("Should handle empty string")
        void shouldHandleEmptyString() {
            assertEquals("", LogSanitizer.sanitize(""));
        }

        @Test
        @DisplayName("Should preserve unicode characters")
        void shouldPreserveUnicode() {
            String unicode = "Hello 世界 🌍";
            assertEquals(unicode, LogSanitizer.sanitize(unicode));
        }

        @Test
        @DisplayName("Should handle CRLF sequences")
        void shouldHandleCRLF() {
            assertEquals("line1_line2", LogSanitizer.sanitize("line1\r\nline2"));
        }
    }

    @Nested
    @DisplayName("maskIdentifier Tests")
    class MaskIdentifierTests {

        @Test
        @DisplayName("Should return empty for null input")
        void shouldReturnEmptyForNull() {
            assertEquals("", LogSanitizer.maskIdentifier(null));
        }

        @Test
        @DisplayName("Should return empty for empty string")
        void shouldReturnEmptyForEmptyString() {
            assertEquals("", LogSanitizer.maskIdentifier(""));
        }

        @Test
        @DisplayName("Should mask single character")
        void shouldMaskSingleChar() {
            assertEquals("*", LogSanitizer.maskIdentifier("X"));
        }

        @Test
        @DisplayName("Should mask short strings (2-4 chars)")
        void shouldMaskShortStrings() {
            assertEquals("a***", LogSanitizer.maskIdentifier("ab"));
            assertEquals("a***", LogSanitizer.maskIdentifier("abc"));
            assertEquals("a***", LogSanitizer.maskIdentifier("abcd"));
        }

        @Test
        @DisplayName("Should mask Ethereum address")
        void shouldMaskEthereumAddress() {
            String address = "0x1234567890abcdef1234567890abcdef12345678";
            String masked = LogSanitizer.maskIdentifier(address);
            
            assertTrue(masked.startsWith("0x1234"));
            assertTrue(masked.contains("..."));
            assertTrue(masked.endsWith("5678"));
            assertFalse(masked.equals(address));
        }

        @Test
        @DisplayName("Should mask reservation key")
        void shouldMaskReservationKey() {
            String key = "0xabc123def456789";
            String masked = LogSanitizer.maskIdentifier(key);
            
            assertTrue(masked.contains("..."));
            assertTrue(masked.length() < key.length());
        }

        @Test
        @DisplayName("Should sanitize control chars before masking")
        void shouldSanitizeBeforeMasking() {
            String withNewline = "0x1234\n567890abcdef";
            String masked = LogSanitizer.maskIdentifier(withNewline);
            
            assertFalse(masked.contains("\n"));
        }

        @Test
        @DisplayName("Should mask medium length string")
        void shouldMaskMediumString() {
            String medium = "secret_value_12345";
            String masked = LogSanitizer.maskIdentifier(medium);
            
            assertTrue(masked.contains("..."));
            assertTrue(masked.length() < medium.length());
        }
    }

    @Nested
    @DisplayName("sanitizeOrDefault Tests")
    class SanitizeOrDefaultTests {

        @Test
        @DisplayName("Should return default for null value")
        void shouldReturnDefaultForNull() {
            assertEquals("default", LogSanitizer.sanitizeOrDefault(null, "default"));
        }

        @Test
        @DisplayName("Should return sanitized value when not null")
        void shouldReturnSanitizedWhenNotNull() {
            assertEquals("hello_world", LogSanitizer.sanitizeOrDefault("hello\nworld", "default"));
        }

        @Test
        @DisplayName("Should return empty string when both value and default are null")
        void shouldReturnEmptyWhenBothNull() {
            assertEquals("", LogSanitizer.sanitizeOrDefault(null, null));
        }

        @Test
        @DisplayName("Should sanitize the value even when default is provided")
        void shouldSanitizeValueWithDefault() {
            String result = LogSanitizer.sanitizeOrDefault("data\twith\ttabs", "fallback");
            assertEquals("data_with_tabs", result);
        }
    }
}
