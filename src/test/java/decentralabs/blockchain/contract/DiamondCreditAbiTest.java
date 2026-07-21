package decentralabs.blockchain.contract;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.abi.datatypes.generated.Uint48;
import org.web3j.abi.datatypes.generated.Uint256;

class DiamondCreditAbiTest {

    @Test
    void decodesCreditLotAndMovementPages() {
        Diamond.CreditLotStruct lot = new Diamond.CreditLotStruct(
            new Uint256(7), new Bytes32(new byte[32]), new Uint256(1000),
            new Uint256(900), new Uint256(10000), new Uint48(100),
            new Uint48(200), new Bool(false)
        );
        Diamond.CreditMovementStruct movement = new Diamond.CreditMovementStruct(
            new Uint8(0), new Uint256(1000), new Uint256(1000),
            new Uint256(0), new Bytes32(new byte[32]), new Uint48(100)
        );

        Function lotsFunction = new Function(
            "testLots",
            Arrays.asList(new DynamicArray<>(List.of(lot)), new Uint256(1)),
            Arrays.asList(
                new TypeReference<DynamicArray<Diamond.CreditLotStruct>>() {},
                new TypeReference<Uint256>() {}
            )
        );
        Function movementsFunction = new Function(
            "testMovements",
            Arrays.asList(new DynamicArray<>(List.of(movement)), new Uint256(1)),
            Arrays.asList(
                new TypeReference<DynamicArray<Diamond.CreditMovementStruct>>() {},
                new TypeReference<Uint256>() {}
            )
        );

        assertThat(FunctionReturnDecoder.decode(
            stripSelector(FunctionEncoder.encode(lotsFunction)),
            lotsFunction.getOutputParameters()
        )).hasSize(2);
        assertThat(FunctionReturnDecoder.decode(
            stripSelector(FunctionEncoder.encode(movementsFunction)),
            movementsFunction.getOutputParameters()
        )).hasSize(2);
    }

    private String stripSelector(String encodedFunction) {
        return encodedFunction.substring(10);
    }
}
