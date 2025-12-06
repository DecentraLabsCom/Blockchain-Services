package decentralabs.blockchain.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("RateLimitService Tests")
class RateLimitServiceTest {

    private RateLimitService service;

    @BeforeEach
    void setUp() {
        service = new RateLimitService();
    }

    @Nested
    @DisplayName("Transaction Rate Limiting Tests")
    class TransactionRateLimitingTests {

        @Test
        @DisplayName("Should allow transactions until limit is reached")
        void shouldAllowTransactionsUntilLimitIsReached() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 2);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 5);

            assertThat(service.allowTransaction("0xabc")).isTrue();
            assertThat(service.allowTransaction("0xabc")).isTrue();
            assertThat(service.allowTransaction("0xabc")).isFalse();
        }

        @Test
        @DisplayName("Should maintain separate limits per wallet")
        void shouldMaintainSeparateLimitsPerWallet() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 1);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 5);

            assertThat(service.allowTransaction("0xwallet1")).isTrue();
            assertThat(service.allowTransaction("0xwallet1")).isFalse();
            
            // Different wallet should have its own limit
            assertThat(service.allowTransaction("0xwallet2")).isTrue();
            assertThat(service.allowTransaction("0xwallet2")).isFalse();
        }

        @Test
        @DisplayName("Should handle high volume requests")
        void shouldHandleHighVolumeRequests() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 100);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 5);

            String wallet = "0xhighvolume";
            int successCount = 0;
            
            for (int i = 0; i < 150; i++) {
                if (service.allowTransaction(wallet)) {
                    successCount++;
                }
            }

            assertThat(successCount).isEqualTo(100);
        }

        @Test
        @DisplayName("Should handle concurrent wallet addresses")
        void shouldHandleConcurrentWalletAddresses() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 5);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 5);

            for (int i = 0; i < 10; i++) {
                String wallet = "0xwallet" + i;
                assertThat(service.allowTransaction(wallet)).isTrue();
            }
        }
    }

    @Nested
    @DisplayName("Balance Check Rate Limiting Tests")
    class BalanceCheckRateLimitingTests {

        @Test
        @DisplayName("Should allow balance checks until limit is reached")
        void shouldAllowBalanceChecksUntilLimitIsReached() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 5);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 2);

            assertThat(service.allowBalanceCheck("0xabc")).isTrue();
            assertThat(service.allowBalanceCheck("0xabc")).isTrue();
            assertThat(service.allowBalanceCheck("0xabc")).isFalse();
        }

        @Test
        @DisplayName("Should maintain separate balance check limits per wallet")
        void shouldMaintainSeparateBalanceCheckLimitsPerWallet() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 5);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 1);

            assertThat(service.allowBalanceCheck("0xwallet1")).isTrue();
            assertThat(service.allowBalanceCheck("0xwallet1")).isFalse();
            
            assertThat(service.allowBalanceCheck("0xwallet2")).isTrue();
            assertThat(service.allowBalanceCheck("0xwallet2")).isFalse();
        }

        @Test
        @DisplayName("Should handle rapid balance check requests")
        void shouldHandleRapidBalanceCheckRequests() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 5);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 50);

            String wallet = "0xrapid";
            int successCount = 0;
            
            for (int i = 0; i < 100; i++) {
                if (service.allowBalanceCheck(wallet)) {
                    successCount++;
                }
            }

            assertThat(successCount).isEqualTo(50);
        }
    }

    @Nested
    @DisplayName("Remaining Tokens Tests")
    class RemainingTokensTests {

        @Test
        @DisplayName("Should report remaining transactions")
        void shouldReportRemainingTransactions() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 3);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 3);

            service.allowTransaction("0xabc");
            assertThat(service.getRemainingTransactions("0xabc")).isEqualTo(2);
        }

        @Test
        @DisplayName("Should report remaining balance checks")
        void shouldReportRemainingBalanceChecks() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 3);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 3);

            service.allowBalanceCheck("0xabc");
            assertThat(service.getRemainingBalanceChecks("0xabc")).isEqualTo(2);
        }

        @Test
        @DisplayName("Should return max when wallet has no bucket yet")
        void shouldReturnMaxWhenNoBucketYet() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 100);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 60);

            assertThat(service.getRemainingTransactions("0xnewwallet")).isEqualTo(100);
            assertThat(service.getRemainingBalanceChecks("0xnewwallet")).isEqualTo(60);
        }

        @Test
        @DisplayName("Should correctly track remaining after multiple calls")
        void shouldCorrectlyTrackRemainingAfterMultipleCalls() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 10);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 10);

            String wallet = "0xtracked";
            
            for (int i = 0; i < 5; i++) {
                service.allowTransaction(wallet);
            }
            
            assertThat(service.getRemainingTransactions(wallet)).isEqualTo(5);
        }

        @Test
        @DisplayName("Should return zero when all tokens consumed")
        void shouldReturnZeroWhenAllTokensConsumed() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 3);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 3);

            String wallet = "0xdrained";
            
            service.allowTransaction(wallet);
            service.allowTransaction(wallet);
            service.allowTransaction(wallet);
            
            assertThat(service.getRemainingTransactions(wallet)).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("Independent Bucket Tests")
    class IndependentBucketTests {

        @Test
        @DisplayName("Transaction and balance check buckets should be independent")
        void transactionAndBalanceCheckBucketsShouldBeIndependent() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 2);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 2);

            String wallet = "0xindependent";

            // Exhaust transaction bucket
            service.allowTransaction(wallet);
            service.allowTransaction(wallet);
            assertThat(service.allowTransaction(wallet)).isFalse();

            // Balance check bucket should still be full
            assertThat(service.allowBalanceCheck(wallet)).isTrue();
            assertThat(service.allowBalanceCheck(wallet)).isTrue();
            assertThat(service.allowBalanceCheck(wallet)).isFalse();
        }

        @Test
        @DisplayName("Consuming balance checks should not affect transactions")
        void consumingBalanceChecksShouldNotAffectTransactions() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 3);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 2);

            String wallet = "0xseparate";

            // Exhaust balance check bucket
            service.allowBalanceCheck(wallet);
            service.allowBalanceCheck(wallet);
            assertThat(service.allowBalanceCheck(wallet)).isFalse();

            // Transaction bucket should still be available
            assertThat(service.getRemainingTransactions(wallet)).isEqualTo(3);
            assertThat(service.allowTransaction(wallet)).isTrue();
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle empty wallet address")
        void shouldHandleEmptyWalletAddress() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 5);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 5);

            // Empty string is still a valid key
            assertThat(service.allowTransaction("")).isTrue();
            assertThat(service.allowBalanceCheck("")).isTrue();
        }

        @Test
        @DisplayName("Should handle single token limit")
        void shouldHandleSingleTokenLimit() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 1);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 1);

            String wallet = "0xsingle";

            assertThat(service.allowTransaction(wallet)).isTrue();
            assertThat(service.allowTransaction(wallet)).isFalse();
            
            assertThat(service.allowBalanceCheck(wallet)).isTrue();
            assertThat(service.allowBalanceCheck(wallet)).isFalse();
        }

        @Test
        @DisplayName("Should handle case-sensitive wallet addresses")
        void shouldHandleCaseSensitiveWalletAddresses() {
            ReflectionTestUtils.setField(service, "maxTransactionsPerHour", 1);
            ReflectionTestUtils.setField(service, "maxBalanceChecksPerMinute", 5);

            // These are treated as different wallets
            assertThat(service.allowTransaction("0xABC")).isTrue();
            assertThat(service.allowTransaction("0xabc")).isTrue();
            
            // Original wallet should be blocked
            assertThat(service.allowTransaction("0xABC")).isFalse();
        }
    }
}
