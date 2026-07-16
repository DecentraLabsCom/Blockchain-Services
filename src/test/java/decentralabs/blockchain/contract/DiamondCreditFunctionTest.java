package decentralabs.blockchain.contract;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.web3j.abi.FunctionEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class DiamondCreditFunctionTest {

    private static final String ACCOUNT = "0x1234567890123456789012345678901234567890";
    private static final byte[] REFERENCE = new byte[32];

    @Test
    void mintCreditsUsesTheLotBackedSelector() {
        var function = Diamond.mintCreditsFunction(
            ACCOUNT,
            BigInteger.valueOf(1_000),
            REFERENCE,
            BigInteger.valueOf(100),
            BigInteger.valueOf(1_900_000_000L)
        );

        assertThat(function.getName()).isEqualTo("mintCredits");
        assertThat(FunctionEncoder.encode(function).substring(0, 10)).isEqualTo(selector(
            "mintCredits(address,uint256,bytes32,uint256,uint48)"
        ));
    }

    @Test
    void ledgerAdjustCreditsUsesTheLotBackedSelector() {
        var function = Diamond.ledgerAdjustCreditsFunction(ACCOUNT, BigInteger.valueOf(-25), REFERENCE);

        assertThat(function.getName()).isEqualTo("ledgerAdjustCredits");
        assertThat(FunctionEncoder.encode(function).substring(0, 10)).isEqualTo(selector(
            "ledgerAdjustCredits(address,int256,bytes32)"
        ));
    }

    @Test
    void totalBalanceOfUsesTheCanonicalBalanceSelector() {
        var function = Diamond.totalBalanceOfFunction(ACCOUNT);

        assertThat(function.getName()).isEqualTo("totalBalanceOf");
        assertThat(FunctionEncoder.encode(function).substring(0, 10)).isEqualTo(selector("totalBalanceOf(address)"));
    }

    private String selector(String signature) {
        return org.web3j.crypto.Hash.sha3String(signature).substring(0, 10);
    }
}
