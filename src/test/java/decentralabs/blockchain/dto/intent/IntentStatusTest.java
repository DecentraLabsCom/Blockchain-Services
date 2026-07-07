package decentralabs.blockchain.dto.intent;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("IntentStatus Tests")
class IntentStatusTest {

    @Nested
    @DisplayName("Enum Value Tests")
    class EnumValueTests {

        @Test
        @DisplayName("Should have QUEUED status")
        void shouldHaveQueuedStatus() {
            assertNotNull(IntentStatus.QUEUED);
            assertEquals("queued", IntentStatus.QUEUED.getWireValue());
        }

        @Test
        @DisplayName("Should have IN_PROGRESS status")
        void shouldHaveInProgressStatus() {
            assertNotNull(IntentStatus.IN_PROGRESS);
            assertEquals("in_progress", IntentStatus.IN_PROGRESS.getWireValue());
        }

        @Test
        @DisplayName("Should have EXECUTED status")
        void shouldHaveExecutedStatus() {
            assertNotNull(IntentStatus.EXECUTED);
            assertEquals("executed", IntentStatus.EXECUTED.getWireValue());
        }

        @Test
        @DisplayName("Should have FAILED status")
        void shouldHaveFailedStatus() {
            assertNotNull(IntentStatus.FAILED);
            assertEquals("failed", IntentStatus.FAILED.getWireValue());
        }

        @Test
        @DisplayName("Should have REJECTED status")
        void shouldHaveRejectedStatus() {
            assertNotNull(IntentStatus.REJECTED);
            assertEquals("rejected", IntentStatus.REJECTED.getWireValue());
        }
    }

    @Nested
    @DisplayName("valueOf Tests")
    class ValueOfTests {

        @Test
        @DisplayName("Should return QUEUED from string")
        void shouldReturnQueuedFromString() {
            assertEquals(IntentStatus.QUEUED, IntentStatus.valueOf("QUEUED"));
        }

        @Test
        @DisplayName("Should return IN_PROGRESS from string")
        void shouldReturnInProgressFromString() {
            assertEquals(IntentStatus.IN_PROGRESS, IntentStatus.valueOf("IN_PROGRESS"));
        }

        @Test
        @DisplayName("Should return EXECUTED from string")
        void shouldReturnExecutedFromString() {
            assertEquals(IntentStatus.EXECUTED, IntentStatus.valueOf("EXECUTED"));
        }

        @Test
        @DisplayName("Should return FAILED from string")
        void shouldReturnFailedFromString() {
            assertEquals(IntentStatus.FAILED, IntentStatus.valueOf("FAILED"));
        }

        @Test
        @DisplayName("Should return REJECTED from string")
        void shouldReturnRejectedFromString() {
            assertEquals(IntentStatus.REJECTED, IntentStatus.valueOf("REJECTED"));
        }

        @Test
        @DisplayName("Should throw exception for invalid value")
        void shouldThrowForInvalidValue() {
            assertThrows(IllegalArgumentException.class, () -> 
                IntentStatus.valueOf("INVALID")
            );
        }
    }

    @Nested
    @DisplayName("values Tests")
    class ValuesTests {

        @Test
        @DisplayName("Should return all values")
        void shouldReturnAllValues() {
            IntentStatus[] values = IntentStatus.values();
            assertEquals(5, values.length);
        }

        @Test
        @DisplayName("Should contain all expected statuses")
        void shouldContainAllExpectedStatuses() {
            IntentStatus[] values = IntentStatus.values();
            
            assertTrue(containsStatus(values, IntentStatus.QUEUED));
            assertTrue(containsStatus(values, IntentStatus.IN_PROGRESS));
            assertTrue(containsStatus(values, IntentStatus.EXECUTED));
            assertTrue(containsStatus(values, IntentStatus.FAILED));
            assertTrue(containsStatus(values, IntentStatus.REJECTED));
        }

        @Test
        @DisplayName("Should have correct ordinals")
        void shouldHaveCorrectOrdinals() {
            assertEquals(0, IntentStatus.QUEUED.ordinal());
            assertEquals(1, IntentStatus.IN_PROGRESS.ordinal());
            assertEquals(2, IntentStatus.EXECUTED.ordinal());
            assertEquals(3, IntentStatus.FAILED.ordinal());
            assertEquals(4, IntentStatus.REJECTED.ordinal());
        }

        private boolean containsStatus(IntentStatus[] values, IntentStatus status) {
            for (IntentStatus s : values) {
                if (s == status) return true;
            }
            return false;
        }
    }
}
