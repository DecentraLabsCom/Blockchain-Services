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
        assertThat(page).contains("id=\"provisioningTokenForm\"");
        assertThat(page).contains("id=\"provisioningTokenInput\"");
        assertThat(page).contains("id=\"applyProvisioningTokenBtn\"");
        assertThat(page).contains("Apply provisioning token");
        assertThat(page).doesNotContain("id=\"marketplaceLink\"");
        assertThat(page).doesNotContain("provisioningTokenModal");
        assertThat(page).doesNotContain("signed provisioning JWT");
        assertThat(page).doesNotContain("applyProvisioningTokenHeaderBtn");
    }

    @Test
    void institutionConfig_exposesNavigationForEachPairingStep() throws IOException {
        String page = readResource("static/institution-config/index.html");
        String script = readResource("static/institution-config/assets/js/pairing.js");
        String styles = readResource("static/wallet-dashboard/assets/css/admin.css");
        String pairingStyles = readResource("static/institution-config/assets/css/pairing.css");

        assertThat(page).contains("id=\"pairingSteps\"");
        assertThat(page).contains("id=\"walletDashboardLink\"");
        assertThat(page).contains("id=\"marketplaceApprovalLink\"");
        assertThat(page).contains("id=\"pairingProgress\"");
        assertThat(page).contains("assets/css/pairing.css");
        assertThat(page).doesNotContain("<style>");
        assertThat(page).contains("role=\"status\"");
        assertThat(page).contains("aria-live=\"polite\"");
        assertThat(page).contains("pairing-progress-spinner");
        assertThat(page).contains("rows=\"2\"");
        assertThat(page).contains("class=\"pairing-form\"");
        assertThat(page).contains("class=\"actions pairing-form-actions\"");
        assertThat(page).doesNotContain("style=");
        assertThat(page).contains("class=\"pairing-instructions\"");
        assertThat(page).contains("Open Marketplace to generate pairing challenge");
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
        assertThat(script).contains("challengeField.addEventListener('input'");
        assertThat(script).contains("isValidPairingChallenge");
        assertThat(script).contains("function updateMarketplaceLink");
        assertThat(script).contains("Open Marketplace to generate pairing challenge");
        assertThat(script).contains("Open Marketplace to approve pairing");
        assertThat(script).contains("currentStep === 1");
        assertThat(script).contains("currentStep === 3");
        assertThat(script).contains("updateSteps(3)");
        assertThat(script).contains("updateSteps(4)");
        assertThat(script).contains("updateSteps(5)");
        assertThat(script).contains("function showError");
        assertThat(script).contains("configured public backend origin is required");
        assertThat(script).contains("setPairingProgress('', { tone: 'info' })");
        assertThat(script).contains("Completing pairing with approved server-side credentials");
        assertThat(script).contains("Offering backend identity");
        assertThat(script).contains("then complete pairing here");
        assertThat(script).doesNotContain("Review and approve the read-only wallet and origin values");
        assertThat(script).doesNotContain("apply-provider-token");
        assertThat(script).doesNotContain("apply-consumer-token");
        assertThat(styles).contains(".pairing-flow-steps li.is-current {");
        assertThat(styles).contains("box-shadow:");
        assertThat(pairingStyles).contains("min-height: 3.75rem;");
        assertThat(pairingStyles).contains("margin: 1.25rem 0 1.25rem 2rem;");
        assertThat(pairingStyles).contains("padding: 0 0 0 2rem;");
        assertThat(pairingStyles).contains("margin-top: 2rem;");
        assertThat(pairingStyles).contains("#pairingForm.pairing-form");
        assertThat(pairingStyles).contains("gap: 1.25rem;");
        assertThat(pairingStyles).contains(".pairing-form-actions");
        assertThat(pairingStyles).contains("justify-content: center;");
        assertThat(pairingStyles).contains("background: var(--bg-secondary);");
        assertThat(pairingStyles).contains("color: var(--text-primary);");
        assertThat(pairingStyles).contains(".alert.is-visible");
        assertThat(pairingStyles).contains(".readonly-value code");
    }

    @Test
    void walletDashboardScriptOffersDirectProvisioningTokenFlow() throws IOException {
        String page = readResource("static/wallet-dashboard/index.html");
        String script = readResource("static/wallet-dashboard/assets/js/admin.js");
        String apiScript = readResource("static/wallet-dashboard/assets/js/api.js");

        assertThat(page).contains("Apply provisioning token");
        assertThat(page).contains("Open backend pairing setup");
        assertThat(script).contains("institutionPairingSection");
        assertThat(script).contains("openInstitutionConfigHeaderBtn");
        assertThat(script).contains("applyProvisioningToken");
        assertThat(script).contains("provisioningTokenForm");
        assertThat(script).contains("registered !== true");
        assertThat(script).doesNotContain("console.log('Provisioning token");
        assertThat(apiScript).contains("/institution-config/apply-provider-token");
        assertThat(apiScript).contains("/institution-config/apply-consumer-token");
    }

    private String readResource(String path) throws IOException {
        try (InputStream stream = getClass().getClassLoader().getResourceAsStream(path)) {
            assertThat(stream).as("resource %s", path).isNotNull();
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
