package decentralabs.blockchain.service.billing;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.datatypes.Event;

import static org.assertj.core.api.Assertions.assertThat;

class OnChainAdminTransactionServiceCreditEventTest {

    @Test
    void creditEventsUseTheLotBackedContractSignatures() {
        Event minted = (Event) ReflectionTestUtils.getField(
            OnChainAdminTransactionService.class,
            "CREDIT_LOT_MINTED_EVENT"
        );
        Event adjusted = (Event) ReflectionTestUtils.getField(
            OnChainAdminTransactionService.class,
            "CREDIT_LOT_ADJUSTED_EVENT"
        );

        assertThat(EventEncoder.encode(minted)).isEqualTo(topic(
            "CreditLotMinted(address,uint256,uint256,uint256,bytes32,uint48)"
        ));
        assertThat(EventEncoder.encode(adjusted)).isEqualTo(topic(
            "CreditLotAdjusted(address,int256,uint256,bytes32)"
        ));
    }

    private String topic(String signature) {
        return org.web3j.crypto.Hash.sha3String(signature);
    }
}
