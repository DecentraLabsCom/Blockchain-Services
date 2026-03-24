package decentralabs.blockchain.service.billing;

import static org.assertj.core.api.Assertions.assertThat;

import decentralabs.blockchain.dto.billing.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.billing.InstitutionalAdminRequest.AdminOperation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

class Eip712BillingAdminVerifierTest {

    private Eip712BillingAdminVerifier verifier;
    private Credentials credentials;

    @BeforeEach
    void setUp() {
        verifier = new Eip712BillingAdminVerifier(
            "DecentraLabsTreasuryAdmin",
            "1",
            11155111L,
            "0x2222222222222222222222222222222222222222"
        );
        credentials = Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");
    }

    @Test
    void verify_acceptsValidSignature() {
        InstitutionalAdminRequest request = request(
            credentials.getAddress(),
            AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE
        );
        request.setProviderAddress("0x1111111111111111111111111111111111111111");
        request.setBackendAddress("0x3333333333333333333333333333333333333333");
        request.setSpendingLimit("1000");
        request.setSpendingPeriod("3600");
        request.setAmount("250");
        request.setLabId("42");
        request.setMaxBatch("8");
        request.setCreditAccount("0x4444444444444444444444444444444444444444");
        request.setCreditDelta("-125");
        request.setFromReceivableState("2");
        request.setToReceivableState("3");
        request.setReference("adj-2026-03-20");
        request.setSignature(sign(request, credentials));

        Eip712BillingAdminVerifier.VerificationResult result = verifier.verify(request, credentials.getAddress());

        assertThat(result.valid()).isTrue();
        assertThat(result.recoveredAddress()).isEqualToIgnoringCase(credentials.getAddress());
        assertThat(result.error()).isNull();
    }

    @Test
    void verify_rejectsMissingOperation() {
        Eip712BillingAdminVerifier.VerificationResult result = verifier.verify(null, credentials.getAddress());

        assertThat(result.valid()).isFalse();
        assertThat(result.recoveredAddress()).isNull();
        assertThat(result.error()).isEqualTo("missing_operation");
    }

    @Test
    void verify_rejectsMissingSignature() {
        InstitutionalAdminRequest request = request(credentials.getAddress(), AdminOperation.AUTHORIZE_BACKEND);

        Eip712BillingAdminVerifier.VerificationResult result = verifier.verify(request, credentials.getAddress());

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).isEqualTo("missing_signature");
    }

    @Test
    void verify_rejectsMissingTimestamp() {
        InstitutionalAdminRequest request = request(credentials.getAddress(), AdminOperation.AUTHORIZE_BACKEND);
        request.setTimestamp(null);
        request.setSignature("0x1234");

        Eip712BillingAdminVerifier.VerificationResult result = verifier.verify(request, credentials.getAddress());

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).isEqualTo("missing_timestamp");
    }

    @Test
    void verify_rejectsMissingExpectedSigner() {
        InstitutionalAdminRequest request = request(credentials.getAddress(), AdminOperation.AUTHORIZE_BACKEND);
        request.setSignature("0x1234");

        Eip712BillingAdminVerifier.VerificationResult result = verifier.verify(request, " ");

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).isEqualTo("missing_expected_signer");
    }

    @Test
    void verify_rejectsSignerMismatchBeforeRecoveringSignature() {
        InstitutionalAdminRequest request = request("0x1111111111111111111111111111111111111111", AdminOperation.AUTHORIZE_BACKEND);
        request.setSignature("0x1234");

        Eip712BillingAdminVerifier.VerificationResult result = verifier.verify(
            request,
            "0x2222222222222222222222222222222222222222"
        );

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).isEqualTo("signer_mismatch");
    }

    @Test
    void verify_rejectsMalformedSignature() {
        InstitutionalAdminRequest request = request(credentials.getAddress(), AdminOperation.AUTHORIZE_BACKEND);
        request.setSignature("0x1234");

        Eip712BillingAdminVerifier.VerificationResult result = verifier.verify(request, credentials.getAddress());

        assertThat(result.valid()).isFalse();
        assertThat(result.recoveredAddress()).isNull();
        assertThat(result.error()).contains("Invalid signature length");
    }

    @Test
    void verify_rejectsSignatureSignedByDifferentWallet() {
        Credentials wrongSigner = Credentials.create("6c8753cf4a5f2d7a1cb1882df97adf7d2473d786ebc8509ad7d6ef1d5c00f4df");
        InstitutionalAdminRequest request = request(credentials.getAddress(), AdminOperation.COLLECT_LAB_PAYOUT);
        request.setAmount("100");
        request.setSignature(sign(request, wrongSigner));

        Eip712BillingAdminVerifier.VerificationResult result = verifier.verify(request, credentials.getAddress());

        assertThat(result.valid()).isFalse();
        assertThat(result.recoveredAddress()).isNotNull();
        assertThat(result.recoveredAddress()).isNotEqualToIgnoringCase(credentials.getAddress());
        assertThat(result.error()).isEqualTo("signature_mismatch");
    }

    @Test
    void buildDigest_isDeterministicAndDefaultsBlankNumbersToZero() {
        InstitutionalAdminRequest first = request(credentials.getAddress(), AdminOperation.COLLECT_LAB_PAYOUT);
        InstitutionalAdminRequest second = request(credentials.getAddress(), AdminOperation.COLLECT_LAB_PAYOUT);
        second.setProviderAddress("");
        second.setBackendAddress("");
        second.setSpendingLimit("");
        second.setSpendingPeriod("");
        second.setAmount("");
        second.setLabId("");
        second.setMaxBatch("");
        second.setCreditAccount("");
        second.setCreditDelta("");
        second.setFromReceivableState("");
        second.setToReceivableState("");
        second.setReference("");

        byte[] digestA = verifier.buildDigest(first);
        byte[] digestB = verifier.buildDigest(first);
        byte[] digestC = verifier.buildDigest(second);

        assertThat(digestA).containsExactly(digestB);
        assertThat(digestA).containsExactly(digestC);
    }

    @Test
    void buildDigest_changesWhenReceivableLifecycleStateChanges() {
        InstitutionalAdminRequest queuedToInvoiced = request(
            credentials.getAddress(),
            AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE
        );
        queuedToInvoiced.setLabId("12");
        queuedToInvoiced.setAmount("1000");
        queuedToInvoiced.setFromReceivableState("2");
        queuedToInvoiced.setToReceivableState("3");

        InstitutionalAdminRequest approvedToPaid = request(
            credentials.getAddress(),
            AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE
        );
        approvedToPaid.setLabId("12");
        approvedToPaid.setAmount("1000");
        approvedToPaid.setFromReceivableState("4");
        approvedToPaid.setToReceivableState("5");

        assertThat(verifier.buildDigest(queuedToInvoiced))
            .isNotEqualTo(verifier.buildDigest(approvedToPaid));
    }

    private InstitutionalAdminRequest request(String signer, AdminOperation operation) {
        InstitutionalAdminRequest request = new InstitutionalAdminRequest();
        request.setAdminWalletAddress(signer);
        request.setOperation(operation);
        request.setTimestamp(1_710_000_000L);
        return request;
    }

    private String sign(InstitutionalAdminRequest request, Credentials signer) {
        byte[] digest = verifier.buildDigest(request);
        Sign.SignatureData signature = Sign.signMessage(digest, signer.getEcKeyPair(), false);
        byte[] bytes = new byte[65];
        System.arraycopy(signature.getR(), 0, bytes, 0, 32);
        System.arraycopy(signature.getS(), 0, bytes, 32, 32);
        bytes[64] = signature.getV()[0];
        return Numeric.toHexString(bytes);
    }
}
