package decentralabs.blockchain.service.persistence;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class AntiReplayServiceTest {

    private AntiReplayService service;

    @BeforeEach
    void setUp() {
        service = new AntiReplayService();
    }

    @Test
    void shouldDetectReplayWhenTimestampReused() {
        String wallet = "0xabc";
        long timestamp = 123456789L;

        assertThat(service.isTimestampUsed(wallet, timestamp)).isFalse();
        assertThat(service.isTimestampUsed(wallet, timestamp)).isTrue();
        assertThat(service.getTrackedTimestampCount()).isEqualTo(1);
    }

    @Test
    void shouldCleanupExpiredEntries() {
        @SuppressWarnings("unchecked")
        Map<String, Long> cache = (Map<String, Long>) ReflectionTestUtils.getField(service, "usedTimestamps");
        
        // Verify cache is not null before using it
        assertThat(cache).isNotNull();
        
        // Add a stale entry (10 minutes old)
        if (cache != null) {
            cache.put("stale", System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(10));
        }

        // Trigger cleanup by adding a new timestamp
        service.isTimestampUsed("0xdef", System.currentTimeMillis());

        // Verify stale entry was removed
        assertThat(cache).doesNotContainKey("stale");
    }

    @Test
    void shouldClearAllTrackedTimestamps() {
        service.isTimestampUsed("0xabc", System.currentTimeMillis());
        service.clearAll();
        assertThat(service.getTrackedTimestampCount()).isZero();
    }
}
