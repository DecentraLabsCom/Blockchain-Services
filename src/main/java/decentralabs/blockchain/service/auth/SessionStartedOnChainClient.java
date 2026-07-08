package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.DynamicStruct;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.tx.TransactionManager;
import org.web3j.utils.Numeric;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionStartedOnChainClient {

    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;
    private final SessionStartedAttestationSigner signer;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${ethereum.gas.limit.session-started:600000}")
    private BigInteger gasLimit;

    @Value("${ethereum.gas.price.default:1}")
    private BigInteger gasPriceGwei;

    @Value("${session.attestation.publisher.receipt.max-attempts:40}")
    private int receiptMaxAttempts;

    @Value("${session.attestation.publisher.receipt.poll-interval-ms:1500}")
    private long receiptPollIntervalMs;

    public boolean hasSessionStarted(String reservationKey) {
        Web3j web3j = walletService.getWeb3jInstance();
        Function function = new Function(
            "hasReservationSessionStarted",
            List.of(new Bytes32(toBytes32(reservationKey))),
            List.of(new TypeReference<Bool>() { })
        );
        String encoded = FunctionEncoder.encode(function);
        try {
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encoded),
                DefaultBlockParameterName.LATEST
            ).send();
            if (response == null) {
                throw new IllegalStateException("empty eth_call response");
            }
            if (response.hasError()) {
                throw new IllegalStateException(response.getError().getMessage());
            }
            @SuppressWarnings("unchecked")
            List<Type<?>> decoded = (List<Type<?>>) (List<?>) FunctionReturnDecoder.decode(
                response.getValue(),
                function.getOutputParameters()
            );
            return !decoded.isEmpty() && Boolean.TRUE.equals(decoded.getFirst().getValue());
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to query SessionStarted status: " + ex.getMessage(), ex);
        }
    }

    public String markSessionStarted(SessionStartedOnChainSubmission submission) {
        validate(submission);

        Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
        Web3j web3j = walletService.getWeb3jInstance();
        long chainId = getChainId(web3j);
        validateDomainChainId(chainId);
        TransactionManager txManager = new FastRawTransactionManager(web3j, credentials, chainId);

        Function function = new Function(
            "markSessionStarted",
            List.of(new DynamicStruct(
                new Address(normalizeAddress(submission.signerAddress())),
                new Bytes32(toBytes32(submission.reservationKey())),
                new Utf8String(nullToEmpty(submission.labId())),
                new Bytes32(toBytes32(submission.pucHash())),
                new Utf8String(nullToEmpty(submission.gatewayId())),
                new Utf8String(nullToEmpty(submission.sessionId())),
                new Utf8String(nullToEmpty(submission.accessType())),
                new Uint64(BigInteger.valueOf(submission.startedAt())),
                new Bytes32(toBytes32(submission.nonce())),
                new Bytes32(toBytes32(submission.credentialHash())),
                new Bytes32(toBytes32(submission.clientProofHash())),
                new DynamicBytes(Numeric.hexStringToByteArray(submission.signature()))
            )),
            List.of()
        );

        String encoded = FunctionEncoder.encode(function);
        EthSendTransaction tx;
        try {
            tx = txManager.sendTransaction(
                toWei(gasPriceGwei),
                gasLimit,
                contractAddress,
                encoded,
                BigInteger.ZERO
            );
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to send SessionStarted transaction: " + ex.getMessage(), ex);
        }

        String txHash = tx.getTransactionHash();
        if (txHash == null || tx.hasError()) {
            String error = tx.getError() != null ? tx.getError().getMessage() : "tx_hash_missing";
            throw new IllegalStateException("SessionStarted transaction failed: " + error);
        }

        TransactionReceipt receipt = waitForReceipt(web3j, txHash);
        if (!receipt.isStatusOK()) {
            String status = receipt.getStatus() != null ? receipt.getStatus() : "unknown";
            throw new IllegalStateException("SessionStarted transaction was mined but failed. Status: " + status);
        }
        return txHash;
    }

    private TransactionReceipt waitForReceipt(Web3j web3j, String txHash) {
        int attempts = Math.max(1, receiptMaxAttempts);
        long pollInterval = Math.max(0L, receiptPollIntervalMs);

        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                var response = web3j.ethGetTransactionReceipt(txHash).send();
                if (response != null && response.getTransactionReceipt().isPresent()) {
                    return response.getTransactionReceipt().get();
                }
            } catch (Exception ex) {
                throw new IllegalStateException("Failed to confirm SessionStarted transaction: " + ex.getMessage(), ex);
            }

            if (attempt < attempts && pollInterval > 0L) {
                try {
                    Thread.sleep(pollInterval);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Interrupted while waiting for SessionStarted confirmation", ex);
                }
            }
        }

        throw new IllegalStateException(
            "SessionStarted transaction was not confirmed after " + attempts + " receipt poll attempts: " + txHash
        );
    }

    private long getChainId(Web3j web3j) {
        try {
            EthChainId id = web3j.ethChainId().send();
            if (id == null || id.getChainId() == null) {
                return 0L;
            }
            return id.getChainId().longValue();
        } catch (Exception ex) {
            log.warn("Unable to resolve chainId for SessionStarted publication: {}", ex.getMessage());
            return 0L;
        }
    }

    private void validateDomainChainId(long connectedChainId) {
        if (connectedChainId <= 0L) {
            throw new IllegalStateException("Unable to verify connected chainId for SessionStarted publication");
        }
        long domainChainId = signer.getDomainChainId();
        if (domainChainId != connectedChainId) {
            throw new IllegalStateException(
                "SessionStarted domain chainId " + domainChainId
                    + " does not match connected chainId " + connectedChainId
            );
        }
    }

    private void validate(SessionStartedOnChainSubmission submission) {
        if (submission == null) {
            throw new IllegalArgumentException("SessionStarted submission is required");
        }
        requireText(submission.reservationKey(), "reservationKey");
        requireText(submission.labId(), "labId");
        requireText(submission.pucHash(), "pucHash");
        requireText(submission.signerAddress(), "signerAddress");
        requireText(submission.sessionId(), "sessionId");
        requireText(submission.accessType(), "accessType");
        requireText(submission.nonce(), "nonce");
        requireText(submission.credentialHash(), "credentialHash");
        requireText(submission.signature(), "signature");
    }

    private void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("SessionStarted " + field + " is required");
        }
    }

    private BigInteger toWei(BigInteger gwei) {
        if (gwei == null) {
            return BigInteger.ZERO;
        }
        return org.web3j.utils.Convert.toWei(gwei.toString(), org.web3j.utils.Convert.Unit.GWEI).toBigInteger();
    }

    private byte[] toBytes32(String hex) {
        if (hex == null || hex.isBlank()) {
            return new byte[32];
        }
        byte[] raw = Numeric.hexStringToByteArray(hex);
        if (raw.length == 32) {
            return raw;
        }
        byte[] out = new byte[32];
        int start = 32 - raw.length;
        if (start < 0) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, start, raw.length);
        }
        return out;
    }

    private String normalizeAddress(String address) {
        String clean = Numeric.cleanHexPrefix(address == null ? "" : address.trim());
        if (clean.length() > 40) {
            clean = clean.substring(clean.length() - 40);
        }
        if (clean.length() < 40) {
            clean = "0".repeat(40 - clean.length()) + clean;
        }
        return "0x" + clean.toLowerCase();
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
