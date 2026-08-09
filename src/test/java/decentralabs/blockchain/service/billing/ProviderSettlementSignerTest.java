package decentralabs.blockchain.service.billing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import decentralabs.blockchain.service.wallet.ProviderSettlementSigner;
import org.junit.jupiter.api.Test;

class ProviderSettlementSignerTest {

    private static final String APPROVER_KEY =
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001";
    private static final String PAYER_KEY =
        "6c8753d3f2c7d4b9b6a1e5f7a9c3d2e1f0b8c7d6e5f4a3b2c1d0e9f8a7b6c502";

    @Test
    void derivesDistinctAddressesForApprovalAndPayment() {
        ProviderSettlementSigner signer = new ProviderSettlementSigner(APPROVER_KEY, PAYER_KEY);

        assertThat(signer.approverAddress()).isNotEqualToIgnoringCase(signer.payerAddress());
        signer.requireDistinctSigners();
    }

    @Test
    void rejectsMissingSignerConfiguration() {
        ProviderSettlementSigner signer = new ProviderSettlementSigner(APPROVER_KEY, "");

        assertThatThrownBy(signer::requireDistinctSigners)
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("payer");
    }

    @Test
    void rejectsTheSameSignerForBothTransitions() {
        ProviderSettlementSigner signer = new ProviderSettlementSigner(APPROVER_KEY, APPROVER_KEY);

        assertThatThrownBy(signer::requireDistinctSigners)
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("distinct");
    }
}
