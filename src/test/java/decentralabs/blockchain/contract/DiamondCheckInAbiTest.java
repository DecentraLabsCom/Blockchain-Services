package decentralabs.blockchain.contract;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.web3j.abi.FunctionEncoder;

class DiamondCheckInAbiTest {

    @Test
    void encodesCurrentReservationCheckInSelectors() {
        assertThat(FunctionEncoder.encode(
            Diamond.emergencyCheckInFunction(new byte[32], BigInteger.ONE)
        )).startsWith("0x4f90052d");
        assertThat(FunctionEncoder.encode(
            Diamond.reviewEmergencyCheckInFunction(new byte[32])
        )).startsWith("0xb51237e5");
        assertThat(FunctionEncoder.encode(
            Diamond.getEmergencyCheckInReviewFunction(new byte[32])
        )).startsWith("0x5d9f0622");
        assertThat(FunctionEncoder.encode(
            Diamond.checkInReservationWithSignatureFunction(
                new byte[32], "0x0000000000000000000000000000000000000001",
                new byte[32], BigInteger.ONE, new byte[] {1, 2, 3}
            )
        )).startsWith("0x39494b5f");
    }
}
