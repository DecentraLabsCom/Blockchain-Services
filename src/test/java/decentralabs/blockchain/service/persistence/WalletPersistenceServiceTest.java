package decentralabs.blockchain.service.persistence;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("WalletPersistenceService Tests")
class WalletPersistenceServiceTest {

    @TempDir
    Path tempDir;

    @Nested
    @DisplayName("In-Memory Storage Tests")
    class InMemoryStorageTests {

        @Test
        @DisplayName("Should store wallet in memory when persistence disabled")
        void shouldStoreWalletInMemoryWhenPersistenceDisabled() throws Exception {
            Path file = tempDir.resolve("wallets.json");
            WalletPersistenceService service = createService(false, true, file);

            service.init();
            service.saveWallet("0xabc", "encrypted-data");

            assertThat(service.getWallet("0xabc")).isEqualTo("encrypted-data");
            assertThat(service.walletExists("0xabc")).isTrue();
            assertThat(Files.exists(file)).isFalse();
        }

        @Test
        @DisplayName("Should replace existing wallet when saving new one")
        void shouldReplaceExistingWalletWhenSavingNewOne() {
            Path file = tempDir.resolve("wallets.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            service.saveWallet("0xfirst", "data1");
            assertThat(service.walletExists("0xfirst")).isTrue();
            assertThat(service.getWalletCount()).isEqualTo(1);

            service.saveWallet("0xsecond", "data2");
            assertThat(service.walletExists("0xfirst")).isFalse();
            assertThat(service.walletExists("0xsecond")).isTrue();
            assertThat(service.getWalletCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("Should return null for non-existent wallet")
        void shouldReturnNullForNonExistentWallet() {
            Path file = tempDir.resolve("wallets.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            assertThat(service.getWallet("0xnonexistent")).isNull();
        }

        @Test
        @DisplayName("Should correctly report wallet existence")
        void shouldCorrectlyReportWalletExistence() {
            Path file = tempDir.resolve("wallets.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            assertThat(service.walletExists("0xtest")).isFalse();

            service.saveWallet("0xtest", "data");
            assertThat(service.walletExists("0xtest")).isTrue();
        }

        @Test
        @DisplayName("Should delete wallet from memory")
        void shouldDeleteWalletFromMemory() {
            Path file = tempDir.resolve("wallets.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            service.saveWallet("0xdelete", "data");
            assertThat(service.walletExists("0xdelete")).isTrue();

            service.deleteWallet("0xdelete");
            assertThat(service.walletExists("0xdelete")).isFalse();
            assertThat(service.getWalletCount()).isZero();
        }
    }

    @Nested
    @DisplayName("File Persistence Tests")
    class FilePersistenceTests {

        @Test
        @DisplayName("Should persist wallets to file when enabled")
        void shouldPersistWalletsToFileWhenEnabled() throws Exception {
            Path file = tempDir.resolve("persisted-wallets.json");
            WalletPersistenceService service = createService(true, true, file);
            service.init();

            service.saveWallet("0xdef", "enc");

            assertThat(Files.exists(file)).isTrue();

            WalletPersistenceService reloaded = createService(true, true, file);
            reloaded.init();

            assertThat(reloaded.getWallet("0xdef")).isEqualTo("enc");
            assertThat(reloaded.getWalletCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("Should load wallets from existing file on init")
        void shouldLoadWalletsFromExistingFileOnInit() throws Exception {
            Path file = tempDir.resolve("existing-wallets.json");
            WalletPersistenceService service1 = createService(true, true, file);
            service1.init();
            service1.saveWallet("0xpersisted", "persisted-data");

            // Create new service instance and load from file
            WalletPersistenceService service2 = createService(true, true, file);
            service2.init();

            assertThat(service2.getWallet("0xpersisted")).isEqualTo("persisted-data");
        }

        @Test
        @DisplayName("Should handle missing file gracefully")
        void shouldHandleMissingFileGracefully() {
            Path file = tempDir.resolve("nonexistent.json");
            WalletPersistenceService service = createService(true, true, file);

            // Should not throw
            service.init();

            assertThat(service.getWalletCount()).isZero();
        }

        @Test
        @DisplayName("Should update file when wallet is deleted")
        void shouldUpdateFileWhenWalletDeleted() throws Exception {
            Path file = tempDir.resolve("delete-test.json");
            WalletPersistenceService service = createService(true, true, file);
            service.init();

            service.saveWallet("0xwilldelete", "data");
            assertThat(Files.exists(file)).isTrue();

            service.deleteWallet("0xwilldelete");

            // Reload and verify
            WalletPersistenceService reloaded = createService(true, true, file);
            reloaded.init();
            assertThat(reloaded.walletExists("0xwilldelete")).isFalse();
        }
    }

    @Nested
    @DisplayName("Wallet Count Tests")
    class WalletCountTests {

        @Test
        @DisplayName("Should return zero when no wallets stored")
        void shouldReturnZeroWhenNoWalletsStored() {
            Path file = tempDir.resolve("empty.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            assertThat(service.getWalletCount()).isZero();
        }

        @Test
        @DisplayName("Should return one after storing wallet")
        void shouldReturnOneAfterStoringWallet() {
            Path file = tempDir.resolve("one.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            service.saveWallet("0xone", "data");
            assertThat(service.getWalletCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("Should always return max one due to single wallet policy")
        void shouldAlwaysReturnMaxOneDueToSingleWalletPolicy() {
            Path file = tempDir.resolve("policy.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            service.saveWallet("0xa", "data-a");
            service.saveWallet("0xb", "data-b");
            service.saveWallet("0xc", "data-c");

            // Only the last wallet should exist
            assertThat(service.getWalletCount()).isEqualTo(1);
            assertThat(service.walletExists("0xc")).isTrue();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty wallet address")
        void shouldHandleEmptyWalletAddress() {
            Path file = tempDir.resolve("edge.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            service.saveWallet("", "empty-address-data");
            assertThat(service.getWallet("")).isEqualTo("empty-address-data");
        }

        @Test
        @DisplayName("Should handle large encrypted data")
        void shouldHandleLargeEncryptedData() {
            Path file = tempDir.resolve("large.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            String largeData = "a".repeat(10000);
            service.saveWallet("0xlarge", largeData);

            assertThat(service.getWallet("0xlarge")).isEqualTo(largeData);
        }

        @Test
        @DisplayName("Should handle special characters in data")
        void shouldHandleSpecialCharactersInData() {
            Path file = tempDir.resolve("special.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            String specialData = "data\nwith\ttabs\"and'quotes";
            service.saveWallet("0xspecial", specialData);

            assertThat(service.getWallet("0xspecial")).isEqualTo(specialData);
        }

        @Test
        @DisplayName("Should handle delete of non-existent wallet")
        void shouldHandleDeleteOfNonExistentWallet() {
            Path file = tempDir.resolve("nodelete.json");
            WalletPersistenceService service = createService(false, true, file);
            service.init();

            // Should not throw
            service.deleteWallet("0xnonexistent");
            assertThat(service.getWalletCount()).isZero();
        }
    }

    private WalletPersistenceService createService(boolean persistenceEnabled, boolean fileEnabled, Path path) {
        WalletPersistenceService service = new WalletPersistenceService();
        ReflectionTestUtils.setField(service, "persistenceEnabled", persistenceEnabled);
        ReflectionTestUtils.setField(service, "filePersistenceEnabled", fileEnabled);
        ReflectionTestUtils.setField(service, "walletFilePath", path.toString());
        return service;
    }
}
