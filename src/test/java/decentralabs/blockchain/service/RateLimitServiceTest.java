package decentralabs.blockchain.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitServiceTest {

    private RateLimitService service;

    @BeforeEach
    void setUp() {
        service = new RateLimitService();
    }

    @Test
    void shouldAllowTransactionsUntilLimitIsReached() {
        ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 2);
        ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 5);

        assertThat(service.allowTransaction("0xabc")).isTrue();
        assertThat(service.allowTransaction("0xabc")).isTrue();
        assertThat(service.allowTransaction("0xabc")).isFalse();
    }

    @Test
    void shouldAllowBalanceChecksUntilLimitIsReached() {
        ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 5);
        ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 2);

        assertThat(service.allowBalanceCheck("0xabc")).isTrue();
        assertThat(service.allowBalanceCheck("0xabc")).isTrue();
        assertThat(service.allowBalanceCheck("0xabc")).isFalse();
    }

    @Test
    void shouldReportRemainingTokens() {
        ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 3);
        ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 3);

        service.allowTransaction("0xabc");
        assertThat(service.getRemainingTransactions("0xabc")).isEqualTo(2);

        service.allowBalanceCheck("0xabc");
        assertThat(service.getRemainingBalanceChecks("0xabc")).isEqualTo(2);
    }
}
