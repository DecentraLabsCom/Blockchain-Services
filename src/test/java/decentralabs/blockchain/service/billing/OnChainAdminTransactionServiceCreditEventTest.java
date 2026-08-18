package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.service.health.LabMetadataService;
import java.math.BigInteger;
import java.util.HashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.datatypes.Event;
import org.web3j.protocol.Web3j;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OnChainAdminTransactionServiceCreditEventTest {

    @Mock
    private Web3j web3j;
    @Mock
    private LabMetadataService labMetadataService;

    private OnChainAdminTransactionService service;

    @BeforeEach
    void setUp() {
        service = new OnChainAdminTransactionService(web3j, labMetadataService);
    }

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

    @Test
    void providerPayoutDescriptionsPreferLabMetadataNames() {
        when(labMetadataService.getLabDisplayNameForLab(BigInteger.TWO)).thenReturn("Lab Two");

        String displayName = ReflectionTestUtils.invokeMethod(
            service,
            "resolveLabDisplayName",
            BigInteger.TWO,
            new HashMap<String, String>()
        );

        assertThat(displayName).isEqualTo("Lab Two");
    }

    private String topic(String signature) {
        return org.web3j.crypto.Hash.sha3String(signature);
    }
}
