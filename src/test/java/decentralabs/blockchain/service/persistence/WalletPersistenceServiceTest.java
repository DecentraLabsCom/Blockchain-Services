package decentralabs.blockchain.service.persistence;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class WalletPersistenceServiceTest {

    @TempDir
    Path tempDir;

    @Test
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

    private WalletPersistenceService createService(boolean persistenceEnabled, boolean fileEnabled, Path path) {
        WalletPersistenceService service = new WalletPersistenceService();
        ReflectionTestUtils.setField(service, "persistenceEnabled", persistenceEnabled);
        ReflectionTestUtils.setField(service, "filePersistenceEnabled", fileEnabled);
        ReflectionTestUtils.setField(service, "walletFilePath", path.toString());
        return service;
    }
}
