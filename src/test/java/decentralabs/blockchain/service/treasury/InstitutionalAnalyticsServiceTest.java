package decentralabs.blockchain.service.treasury;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import decentralabs.blockchain.service.treasury.InstitutionalAnalyticsService.TransactionRecord;
import decentralabs.blockchain.service.treasury.InstitutionalAnalyticsService.UserActivity;

class InstitutionalAnalyticsServiceTest {

    private InstitutionalAnalyticsService analyticsService;

    private static final String PROVIDER_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
    private static final String ALT_PROVIDER = "0xabcdef1234567890abcdef1234567890abcdef12";

    @BeforeEach
    void setUp() {
        analyticsService = new InstitutionalAnalyticsService();
    }

    @Nested
    @DisplayName("Transaction Recording Tests")
    class TransactionRecordingTests {

        @Test
        @DisplayName("Should record single transaction")
        void shouldRecordSingleTransaction() {
            TransactionRecord record = createTransaction("0xhash1", "RESERVATION", "Test reservation");

            analyticsService.recordTransaction(PROVIDER_ADDRESS, record);

            List<TransactionRecord> recent = analyticsService.getRecentTransactions(PROVIDER_ADDRESS, 10);
            assertThat(recent).hasSize(1);
            assertThat(recent.get(0).getHash()).isEqualTo("0xhash1");
        }

        @Test
        @DisplayName("Should record multiple transactions in LIFO order")
        void shouldRecordMultipleTransactionsInLifoOrder() {
            analyticsService.recordTransaction(PROVIDER_ADDRESS, createTransaction("0xhash1", "RESERVATION", "First"));
            analyticsService.recordTransaction(PROVIDER_ADDRESS, createTransaction("0xhash2", "TRANSFER", "Second"));
            analyticsService.recordTransaction(PROVIDER_ADDRESS, createTransaction("0xhash3", "CANCEL", "Third"));

            List<TransactionRecord> recent = analyticsService.getRecentTransactions(PROVIDER_ADDRESS, 10);

            assertThat(recent).hasSize(3);
            assertThat(recent.get(0).getHash()).isEqualTo("0xhash3"); // Most recent first
            assertThat(recent.get(1).getHash()).isEqualTo("0xhash2");
            assertThat(recent.get(2).getHash()).isEqualTo("0xhash1");
        }

        @Test
        @DisplayName("Should respect limit parameter when retrieving transactions")
        void shouldRespectLimitParameter() {
            for (int i = 0; i < 10; i++) {
                analyticsService.recordTransaction(PROVIDER_ADDRESS, 
                    createTransaction("0xhash" + i, "TYPE", "Desc " + i));
            }

            List<TransactionRecord> recent = analyticsService.getRecentTransactions(PROVIDER_ADDRESS, 3);

            assertThat(recent).hasSize(3);
        }

        @Test
        @DisplayName("Should return empty list for unknown provider")
        void shouldReturnEmptyListForUnknownProvider() {
            List<TransactionRecord> recent = analyticsService.getRecentTransactions("0xunknown", 10);

            assertThat(recent).isEmpty();
        }

        @Test
        @DisplayName("Should enforce maximum transactions per provider")
        void shouldEnforceMaximumTransactions() {
            // Record more than MAX (100) transactions
            for (int i = 0; i < 150; i++) {
                analyticsService.recordTransaction(PROVIDER_ADDRESS,
                    createTransaction("0xhash" + i, "TYPE", "Desc " + i));
            }

            List<TransactionRecord> recent = analyticsService.getRecentTransactions(PROVIDER_ADDRESS, 200);

            assertThat(recent).hasSize(100);
            // Should keep most recent
            assertThat(recent.get(0).getHash()).isEqualTo("0xhash149");
        }

        @Test
        @DisplayName("Should track transactions separately per provider")
        void shouldTrackTransactionsSeparatelyPerProvider() {
            analyticsService.recordTransaction(PROVIDER_ADDRESS, createTransaction("0xprov1tx", "RESERVATION", "Provider 1"));
            analyticsService.recordTransaction(ALT_PROVIDER, createTransaction("0xprov2tx", "TRANSFER", "Provider 2"));

            List<TransactionRecord> prov1 = analyticsService.getRecentTransactions(PROVIDER_ADDRESS, 10);
            List<TransactionRecord> prov2 = analyticsService.getRecentTransactions(ALT_PROVIDER, 10);

            assertThat(prov1).hasSize(1);
            assertThat(prov1.get(0).getHash()).isEqualTo("0xprov1tx");
            assertThat(prov2).hasSize(1);
            assertThat(prov2.get(0).getHash()).isEqualTo("0xprov2tx");
        }

        @Test
        @DisplayName("Should normalize provider address to lowercase")
        void shouldNormalizeProviderAddressToLowercase() {
            String upperCaseAddr = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12";
            analyticsService.recordTransaction(upperCaseAddr, createTransaction("0xhash", "TYPE", "Desc"));

            List<TransactionRecord> byLower = analyticsService.getRecentTransactions(upperCaseAddr.toLowerCase(), 10);
            List<TransactionRecord> byUpper = analyticsService.getRecentTransactions(upperCaseAddr, 10);

            assertThat(byLower).hasSize(1);
            assertThat(byUpper).hasSize(1);
        }

        @Test
        @DisplayName("Should handle zero limit")
        void shouldHandleZeroLimit() {
            analyticsService.recordTransaction(PROVIDER_ADDRESS, createTransaction("0xhash", "TYPE", "Desc"));

            List<TransactionRecord> recent = analyticsService.getRecentTransactions(PROVIDER_ADDRESS, 0);

            assertThat(recent).isEmpty();
        }

        @Test
        @DisplayName("Should handle negative limit")
        void shouldHandleNegativeLimit() {
            analyticsService.recordTransaction(PROVIDER_ADDRESS, createTransaction("0xhash", "TYPE", "Desc"));

            List<TransactionRecord> recent = analyticsService.getRecentTransactions(PROVIDER_ADDRESS, -5);

            assertThat(recent).isEmpty();
        }
    }

    @Nested
    @DisplayName("User Activity Recording Tests")
    class UserActivityTests {

        @Test
        @DisplayName("Should record single user activity")
        void shouldRecordSingleUserActivity() {
            analyticsService.recordUserActivity(PROVIDER_ADDRESS, "user123@uned.es");

            List<UserActivity> users = analyticsService.getKnownUsers(PROVIDER_ADDRESS, 10);

            assertThat(users).hasSize(1);
            assertThat(users.get(0).getPuc()).isEqualTo("user123@uned.es");
        }

        @Test
        @DisplayName("Should update timestamp on repeated user activity")
        void shouldUpdateTimestampOnRepeatedUserActivity() throws InterruptedException {
            analyticsService.recordUserActivity(PROVIDER_ADDRESS, "user123@uned.es");
            long firstTimestamp = analyticsService.getKnownUsers(PROVIDER_ADDRESS, 10).get(0).getLastSeenEpochMillis();

            Thread.sleep(10);
            analyticsService.recordUserActivity(PROVIDER_ADDRESS, "user123@uned.es");
            long secondTimestamp = analyticsService.getKnownUsers(PROVIDER_ADDRESS, 10).get(0).getLastSeenEpochMillis();

            assertThat(secondTimestamp).isGreaterThan(firstTimestamp);
            // Should still be just one user
            assertThat(analyticsService.getKnownUsers(PROVIDER_ADDRESS, 10)).hasSize(1);
        }

        @Test
        @DisplayName("Should ignore null PUC")
        void shouldIgnoreNullPuc() {
            analyticsService.recordUserActivity(PROVIDER_ADDRESS, null);

            List<UserActivity> users = analyticsService.getKnownUsers(PROVIDER_ADDRESS, 10);

            assertThat(users).isEmpty();
        }

        @Test
        @DisplayName("Should ignore blank PUC")
        void shouldIgnoreBlankPuc() {
            analyticsService.recordUserActivity(PROVIDER_ADDRESS, "   ");

            List<UserActivity> users = analyticsService.getKnownUsers(PROVIDER_ADDRESS, 10);

            assertThat(users).isEmpty();
        }

        @Test
        @DisplayName("Should return users sorted by most recent")
        void shouldReturnUsersSortedByMostRecent() throws InterruptedException {
            analyticsService.recordUserActivity(PROVIDER_ADDRESS, "user1@test.com");
            Thread.sleep(10);
            analyticsService.recordUserActivity(PROVIDER_ADDRESS, "user2@test.com");
            Thread.sleep(10);
            analyticsService.recordUserActivity(PROVIDER_ADDRESS, "user3@test.com");

            List<UserActivity> users = analyticsService.getKnownUsers(PROVIDER_ADDRESS, 10);

            assertThat(users).hasSize(3);
            assertThat(users.get(0).getPuc()).isEqualTo("user3@test.com"); // Most recent first
            assertThat(users.get(1).getPuc()).isEqualTo("user2@test.com");
            assertThat(users.get(2).getPuc()).isEqualTo("user1@test.com");
        }

        @Test
        @DisplayName("Should respect limit parameter when retrieving users")
        void shouldRespectLimitParameterForUsers() {
            for (int i = 0; i < 10; i++) {
                analyticsService.recordUserActivity(PROVIDER_ADDRESS, "user" + i + "@test.com");
            }

            List<UserActivity> users = analyticsService.getKnownUsers(PROVIDER_ADDRESS, 3);

            assertThat(users).hasSize(3);
        }

        @Test
        @DisplayName("Should return empty list for unknown provider users")
        void shouldReturnEmptyListForUnknownProviderUsers() {
            List<UserActivity> users = analyticsService.getKnownUsers("0xunknown", 10);

            assertThat(users).isEmpty();
        }

        @Test
        @DisplayName("Should track users separately per provider")
        void shouldTrackUsersSeparatelyPerProvider() {
            analyticsService.recordUserActivity(PROVIDER_ADDRESS, "prov1user@test.com");
            analyticsService.recordUserActivity(ALT_PROVIDER, "prov2user@test.com");

            List<UserActivity> prov1Users = analyticsService.getKnownUsers(PROVIDER_ADDRESS, 10);
            List<UserActivity> prov2Users = analyticsService.getKnownUsers(ALT_PROVIDER, 10);

            assertThat(prov1Users).hasSize(1);
            assertThat(prov1Users.get(0).getPuc()).isEqualTo("prov1user@test.com");
            assertThat(prov2Users).hasSize(1);
            assertThat(prov2Users.get(0).getPuc()).isEqualTo("prov2user@test.com");
        }

        @Test
        @DisplayName("Should handle zero limit for users")
        void shouldHandleZeroLimitForUsers() {
            analyticsService.recordUserActivity(PROVIDER_ADDRESS, "user@test.com");

            List<UserActivity> users = analyticsService.getKnownUsers(PROVIDER_ADDRESS, 0);

            assertThat(users).isEmpty();
        }
    }

    @Nested
    @DisplayName("Concurrency Tests")
    class ConcurrencyTests {

        @Test
        @DisplayName("Should handle concurrent transaction recording")
        void shouldHandleConcurrentTransactionRecording() throws InterruptedException {
            int threadCount = 10;
            int transactionsPerThread = 20;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            for (int t = 0; t < threadCount; t++) {
                final int threadId = t;
                executor.submit(() -> {
                    try {
                        for (int i = 0; i < transactionsPerThread; i++) {
                            analyticsService.recordTransaction(PROVIDER_ADDRESS,
                                createTransaction("0xthread" + threadId + "tx" + i, "TYPE", "Desc"));
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await(10, TimeUnit.SECONDS);
            executor.shutdown();

            // Should have at most MAX_TRANSACTIONS_PER_PROVIDER (100)
            List<TransactionRecord> recent = analyticsService.getRecentTransactions(PROVIDER_ADDRESS, 200);
            assertThat(recent.size()).isLessThanOrEqualTo(100);
        }

        @Test
        @DisplayName("Should handle concurrent user activity recording")
        void shouldHandleConcurrentUserActivityRecording() throws InterruptedException {
            int threadCount = 10;
            int usersPerThread = 30;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            for (int t = 0; t < threadCount; t++) {
                final int threadId = t;
                executor.submit(() -> {
                    try {
                        for (int i = 0; i < usersPerThread; i++) {
                            analyticsService.recordUserActivity(PROVIDER_ADDRESS,
                                "thread" + threadId + "user" + i + "@test.com");
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await(10, TimeUnit.SECONDS);
            executor.shutdown();

            // Should have at most MAX_TRACKED_USERS_PER_PROVIDER (200)
            List<UserActivity> users = analyticsService.getKnownUsers(PROVIDER_ADDRESS, 500);
            assertThat(users.size()).isLessThanOrEqualTo(200);
        }
    }

    @Nested
    @DisplayName("Null Provider Address Tests")
    class NullProviderAddressTests {

        @Test
        @DisplayName("Should handle null provider address for transactions")
        void shouldHandleNullProviderAddressForTransactions() {
            analyticsService.recordTransaction(null, createTransaction("0xhash", "TYPE", "Desc"));

            List<TransactionRecord> recent = analyticsService.getRecentTransactions(null, 10);

            assertThat(recent).hasSize(1);
        }

        @Test
        @DisplayName("Should handle null provider address for user activity")
        void shouldHandleNullProviderAddressForUserActivity() {
            analyticsService.recordUserActivity(null, "user@test.com");

            List<UserActivity> users = analyticsService.getKnownUsers(null, 10);

            assertThat(users).hasSize(1);
        }
    }

    private TransactionRecord createTransaction(String hash, String type, String description) {
        return new TransactionRecord(
            hash,
            type,
            description,
            "100",
            System.currentTimeMillis(),
            "CONFIRMED"
        );
    }
}
