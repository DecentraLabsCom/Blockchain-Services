package decentralabs.blockchain.service.persistence;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AntiReplayService Tests")
class AntiReplayServiceTest {

    private AntiReplayService service;

    @BeforeEach
    void setUp() {
        service = new AntiReplayService();
    }

    @Nested
    @DisplayName("Replay Detection Tests")
    class ReplayDetectionTests {

        @Test
        @DisplayName("Should detect replay when timestamp is reused")
        void shouldDetectReplayWhenTimestampReused() {
            String wallet = "0xabc";
            long timestamp = 123456789L;

            assertThat(service.isTimestampUsed(wallet, timestamp)).isFalse();
            assertThat(service.isTimestampUsed(wallet, timestamp)).isTrue();
            assertThat(service.getTrackedTimestampCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("Should allow different timestamps for same wallet")
        void shouldAllowDifferentTimestampsForSameWallet() {
            String wallet = "0xabc";

            assertThat(service.isTimestampUsed(wallet, 1000L)).isFalse();
            assertThat(service.isTimestampUsed(wallet, 2000L)).isFalse();
            assertThat(service.isTimestampUsed(wallet, 3000L)).isFalse();

            assertThat(service.getTrackedTimestampCount()).isEqualTo(3);
        }

        @Test
        @DisplayName("Should allow same timestamp for different wallets")
        void shouldAllowSameTimestampForDifferentWallets() {
            long timestamp = 123456789L;

            assertThat(service.isTimestampUsed("0xwallet1", timestamp)).isFalse();
            assertThat(service.isTimestampUsed("0xwallet2", timestamp)).isFalse();
            assertThat(service.isTimestampUsed("0xwallet3", timestamp)).isFalse();

            assertThat(service.getTrackedTimestampCount()).isEqualTo(3);
        }

        @Test
        @DisplayName("Should track timestamps independently per wallet")
        void shouldTrackTimestampsIndependentlyPerWallet() {
            assertThat(service.isTimestampUsed("0xwalletA", 100L)).isFalse();
            assertThat(service.isTimestampUsed("0xwalletB", 100L)).isFalse();

            // Replay for wallet A only
            assertThat(service.isTimestampUsed("0xwalletA", 100L)).isTrue();
            assertThat(service.isTimestampUsed("0xwalletB", 200L)).isFalse();
        }

        @Test
        @DisplayName("Should handle concurrent timestamp checks")
        void shouldHandleConcurrentTimestampChecks() {
            String wallet = "0xconcurrent";
            long baseTimestamp = System.currentTimeMillis();

            // Simulate multiple rapid checks
            for (int i = 0; i < 10; i++) {
                assertThat(service.isTimestampUsed(wallet, baseTimestamp + i)).isFalse();
            }

            assertThat(service.getTrackedTimestampCount()).isEqualTo(10);
        }
    }

    @Nested
    @DisplayName("Cache Cleanup Tests")
    class CacheCleanupTests {

        @Test
        @DisplayName("Should cleanup expired entries")
        void shouldCleanupExpiredEntries() {
            @SuppressWarnings("unchecked")
            Map<String, Long> cache = (Map<String, Long>) ReflectionTestUtils.getField(service, "usedTimestamps");

            assertThat(cache).isNotNull();

            if (cache != null) {
                // Add a stale entry (10 minutes old)
                cache.put("stale", System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(10));
            }

            // Trigger cleanup by adding a new timestamp
            service.isTimestampUsed("0xdef", System.currentTimeMillis());

            assertThat(cache).doesNotContainKey("stale");
        }

        @Test
        @DisplayName("Should keep non-expired entries after cleanup")
        void shouldKeepNonExpiredEntriesAfterCleanup() {
            String wallet = "0xrecent";
            long recentTimestamp = System.currentTimeMillis();

            service.isTimestampUsed(wallet, recentTimestamp);

            @SuppressWarnings("unchecked")
            Map<String, Long> cache = (Map<String, Long>) ReflectionTestUtils.getField(service, "usedTimestamps");
            assertThat(cache).isNotNull();

            // Trigger another check (which triggers cleanup)
            service.isTimestampUsed("0xother", System.currentTimeMillis());

            // Recent entry should still be present
            String key = wallet + "-" + recentTimestamp;
            assertThat(cache).containsKey(key);
        }
    }

    @Nested
    @DisplayName("Cache Management Tests")
    class CacheManagementTests {

        @Test
        @DisplayName("Should clear all tracked timestamps")
        void shouldClearAllTrackedTimestamps() {
            service.isTimestampUsed("0xabc", System.currentTimeMillis());
            service.isTimestampUsed("0xdef", System.currentTimeMillis());
            service.isTimestampUsed("0xghi", System.currentTimeMillis());

            assertThat(service.getTrackedTimestampCount()).isEqualTo(3);

            service.clearAll();

            assertThat(service.getTrackedTimestampCount()).isZero();
        }

        @Test
        @DisplayName("Should correctly report tracked timestamp count")
        void shouldCorrectlyReportTrackedTimestampCount() {
            assertThat(service.getTrackedTimestampCount()).isZero();

            service.isTimestampUsed("0xa", 1L);
            assertThat(service.getTrackedTimestampCount()).isEqualTo(1);

            service.isTimestampUsed("0xb", 2L);
            assertThat(service.getTrackedTimestampCount()).isEqualTo(2);

            service.isTimestampUsed("0xc", 3L);
            assertThat(service.getTrackedTimestampCount()).isEqualTo(3);
        }

        @Test
        @DisplayName("Should handle clear when empty")
        void shouldHandleClearWhenEmpty() {
            assertThat(service.getTrackedTimestampCount()).isZero();
            service.clearAll();
            assertThat(service.getTrackedTimestampCount()).isZero();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle zero timestamp")
        void shouldHandleZeroTimestamp() {
            assertThat(service.isTimestampUsed("0xwallet", 0L)).isFalse();
            assertThat(service.isTimestampUsed("0xwallet", 0L)).isTrue();
        }

        @Test
        @DisplayName("Should handle negative timestamp")
        void shouldHandleNegativeTimestamp() {
            assertThat(service.isTimestampUsed("0xwallet", -1L)).isFalse();
            assertThat(service.isTimestampUsed("0xwallet", -1L)).isTrue();
        }

        @Test
        @DisplayName("Should handle empty wallet address")
        void shouldHandleEmptyWalletAddress() {
            assertThat(service.isTimestampUsed("", 12345L)).isFalse();
            assertThat(service.isTimestampUsed("", 12345L)).isTrue();
        }

        @Test
        @DisplayName("Should handle max long timestamp")
        void shouldHandleMaxLongTimestamp() {
            assertThat(service.isTimestampUsed("0xwallet", Long.MAX_VALUE)).isFalse();
            assertThat(service.isTimestampUsed("0xwallet", Long.MAX_VALUE)).isTrue();
        }
    }
}
