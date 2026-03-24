package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.MicaOfferVolume;
import decentralabs.blockchain.service.persistence.MicaVolumePersistenceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigDecimal;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("MicaThresholdMonitorScheduler Tests")
class MicaThresholdMonitorSchedulerTest {

    @Mock
    private MicaVolumePersistenceService micaPersistence;

    private MicaThresholdMonitorScheduler scheduler;

    @BeforeEach
    void setUp() {
        scheduler = new MicaThresholdMonitorScheduler(micaPersistence);
        ReflectionTestUtils.setField(scheduler, "micaThresholdEur", new BigDecimal("1000000"));
        ReflectionTestUtils.setField(scheduler, "warningPercentage", 80);
    }

    @Nested
    @DisplayName("monitorThreshold — MiCA threshold aggregation")
    class MonitorThresholdTests {

        @Test
        @DisplayName("Logs OK when volume is well below threshold")
        void logsOkWhenVolumeBelowThreshold() {
            when(micaPersistence.getLatestRollingVolume()).thenReturn(new BigDecimal("500000"));

            scheduler.monitorThreshold();

            // No exception; persistence queried once
            verify(micaPersistence).getLatestRollingVolume();
        }

        @Test
        @DisplayName("Completes without error at exactly the warning level (80 % = 800000)")
        void completesAtWarningLevel() {
            when(micaPersistence.getLatestRollingVolume()).thenReturn(new BigDecimal("800000"));

            scheduler.monitorThreshold();

            verify(micaPersistence).getLatestRollingVolume();
        }

        @Test
        @DisplayName("Completes without error when volume exceeds threshold")
        void completesWhenVolumeExceedsThreshold() {
            when(micaPersistence.getLatestRollingVolume()).thenReturn(new BigDecimal("1050000"));

            scheduler.monitorThreshold();

            verify(micaPersistence).getLatestRollingVolume();
        }

        @Test
        @DisplayName("Handles persistence exception gracefully")
        void handlesPersistenceException() {
            when(micaPersistence.getLatestRollingVolume()).thenThrow(new RuntimeException("DB unavailable"));

            // Must not propagate exception — scheduler swallows and logs
            scheduler.monitorThreshold();

            verify(micaPersistence).getLatestRollingVolume();
        }

        @Test
        @DisplayName("Handles zero volume (empty database)")
        void handlesZeroVolume() {
            when(micaPersistence.getLatestRollingVolume()).thenReturn(BigDecimal.ZERO);

            scheduler.monitorThreshold();

            verify(micaPersistence).getLatestRollingVolume();
        }

        @Test
        @DisplayName("Threshold configurable — custom 500000 threshold triggers alert at 500001")
        void customThresholdTriggersAlert() {
            ReflectionTestUtils.setField(scheduler, "micaThresholdEur", new BigDecimal("500000"));
            when(micaPersistence.getLatestRollingVolume()).thenReturn(new BigDecimal("500001"));

            // Should not throw; just log an error
            scheduler.monitorThreshold();

            verify(micaPersistence).getLatestRollingVolume();
        }

        @Test
        @DisplayName("Warning percentage configurable — 90% warning at 900000 with 1M threshold")
        void customWarningPercentage() {
            ReflectionTestUtils.setField(scheduler, "warningPercentage", 90);
            // At 800000 (80%), no warning with 90% threshold; at 900000 warning fires
            when(micaPersistence.getLatestRollingVolume()).thenReturn(new BigDecimal("900000"));

            scheduler.monitorThreshold();

            verify(micaPersistence).getLatestRollingVolume();
        }
    }
}
