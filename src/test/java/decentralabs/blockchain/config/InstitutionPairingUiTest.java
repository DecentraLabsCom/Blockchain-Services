package decentralabs.blockchain.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class InstitutionPairingUiTest {

    @Test
    void walletDashboard_exposesTheCanonicalPairingFlow() throws IOException {
        String page = readResource("static/wallet-dashboard/index.html");

        assertThat(page).contains("id=\"institutionPairingSection\"");
        assertThat(page).contains("id=\"openInstitutionConfigBtn\"");
        assertThat(page).contains("href=\"/institution-config/\"");
        assertThat(page).contains("Pairing challenge");
        assertThat(page).contains("Wallet ready for pairing.");
        assertThat(page).contains("Generate a short-lived pairing challenge");
        assertThat(page.toLowerCase()).doesNotContain("obtain a provisioning token");
        assertThat(page.toLowerCase()).doesNotContain("enter a provisioning token");
        assertThat(page).doesNotContain("provisioningTokenModal");
        assertThat(page).doesNotContain("signed provisioning JWT");
        assertThat(page).doesNotContain("applyProvisioningTokenHeaderBtn");
    }

    @Test
    void institutionConfig_exposesNavigationForEachPairingStep() throws IOException {
        String page = readResource("static/institution-config/index.html");
        String script = readResource("static/institution-config/assets/js/pairing.js");

        assertThat(page).contains("id=\"pairingSteps\"");
        assertThat(page).contains("id=\"walletDashboardLink\"");
        assertThat(page).contains("id=\"marketplaceApprovalLink\"");
        assertThat(page).contains("id=\"pairingProgress\"");
        assertThat(page).contains("role=\"status\"");
        assertThat(page).contains("aria-live=\"polite\"");
        assertThat(page).contains("pairing-progress-spinner");
        assertThat(page).contains("rows=\"2\"");
        assertThat(page).contains("min-height: 3.75rem; height: 3.75rem");
        assertThat(page).contains("margin-top: 1.5rem");
        assertThat(page).contains(".pairing-details { margin-top: 1.25rem; }");
        assertThat(page).doesNotContain("style=");
        assertThat(page).contains("class=\"pairing-instructions\"");
        assertThat(page).contains("<li><strong>Step 1:</strong>");
        assertThat(page).contains("<li><strong>Step 4:</strong>");
        assertThat(page).doesNotContain("id=\"marketplaceBaseUrl\"");
        assertThat(page).doesNotContain("id=\"backendOrigin\"");
        assertThat(page).doesNotContain("<strong>Institutional wallet</strong>");
        assertThat(page).contains("Complete pairing after approval");
        assertThat(page).doesNotContain("Finalize registration");
        assertThat(page).contains("assets/js/pairing.js");
        assertThat(script).contains("apply-pairing-challenge");
        assertThat(script).contains("complete-pairing");
        assertThat(script).contains("setPairingProgress");
        assertThat(script).contains("function showError");
        assertThat(script).contains("configured public backend origin is required");
        assertThat(script).contains("setPairingProgress('', { tone: 'info' })");
        assertThat(script).contains("Completing pairing with approved server-side credentials");
        assertThat(script).contains("Offering backend identity");
        assertThat(script).contains("then return here to complete pairing");
        assertThat(script).doesNotContain("apply-provider-token");
        assertThat(script).doesNotContain("apply-consumer-token");
    }

    @Test
    void walletDashboardScriptDoesNotExposeJwtAlternative() throws IOException {
        String script = readResource("static/wallet-dashboard/assets/js/admin.js");

        assertThat(script).contains("institutionPairingSection");
        assertThat(script).contains("openInstitutionConfigHeaderBtn");
        assertThat(script).doesNotContain("applyProvisioningToken");
        assertThat(script).doesNotContain("apply-provider-token");
        assertThat(script).doesNotContain("apply-consumer-token");
        assertThat(script).doesNotContain("provisioningTokenModal");
    }

    private String readResource(String path) throws IOException {
        try (InputStream stream = getClass().getClassLoader().getResourceAsStream(path)) {
            assertThat(stream).as("resource %s", path).isNotNull();
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
