package decentralabs.blockchain.contract;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint32;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.abi.datatypes.generated.Uint96;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.Contract;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.ContractGasProvider;

/**
 * Auto-generated wrapper for Diamond contract
 * 
 * <p>Generated with web3j version 4.12.3.
 */
public class Diamond extends Contract {
    
    public static final String BINARY = "";  // Not needed for already deployed contracts
    
    protected Diamond(String contractAddress, Web3j web3j, Credentials credentials,
                     ContractGasProvider contractGasProvider) {
        super(BINARY, contractAddress, web3j, credentials, contractGasProvider);
    }
    
    protected Diamond(String contractAddress, Web3j web3j, TransactionManager transactionManager,
                     ContractGasProvider contractGasProvider) {
        super(BINARY, contractAddress, web3j, transactionManager, contractGasProvider);
    }
    
    // Reservation struct - Simple POJO
    // NOTE: The on-chain Reservation struct does not contain the "puc" string field.
    // PUC verification is performed via getReservationPucHash(bytes32) which returns a keccak256 hash.
    public static class Reservation {
        public BigInteger labId;               // uint256 - lab token ID
        public String renter;                  // address
        public BigInteger price;               // uint96 - reservation price
        public String labProvider;             // address
        public BigInteger status;              // uint8 - reservation status
        public BigInteger start;               // uint32 - start timestamp
        public BigInteger end;                 // uint32 - end timestamp
        public BigInteger requestPeriodStart;  // uint64 - institutional request window start
        public BigInteger requestPeriodDuration; // uint64 - institutional request window duration
        public String payerInstitution;        // address - institution paying for reservation
        public String collectorInstitution;    // address - institution receiving payout
        public BigInteger providerShare;       // uint96 - provider allocation (platform margin is implicit)

        public Reservation(
            BigInteger labId,
            String renter,
            BigInteger price,
            String labProvider,
            BigInteger status,
            BigInteger start,
            BigInteger end,
            BigInteger requestPeriodStart,
            BigInteger requestPeriodDuration,
            String payerInstitution,
            String collectorInstitution,
            BigInteger providerShare
        ) {
            this.labId = labId;
            this.renter = renter;
            this.price = price;
            this.labProvider = labProvider;
            this.status = status;
            this.start = start;
            this.end = end;
            this.requestPeriodStart = requestPeriodStart;
            this.requestPeriodDuration = requestPeriodDuration;
            this.payerInstitution = payerInstitution;
            this.collectorInstitution = collectorInstitution;
            this.providerShare = providerShare;
        }
    }
    
    // LabBase struct - Simple POJO
    public static class LabBase {
        public String uri;        // metadata URI
        public BigInteger price;  // uint96 in Solidity
        public String accessURI;  // access URI
        public String accessKey;  // access key
        public BigInteger createdAt; // uint32
        public BigInteger resourceType; // uint8: 0 = physical lab, 1 = FMU simulation

        public LabBase(String uri, BigInteger price, String accessURI,
                      String accessKey, BigInteger createdAt, BigInteger resourceType) {
            this.uri = uri;
            this.price = price;
            this.accessURI = accessURI;
            this.accessKey = accessKey;
            this.createdAt = createdAt;
            this.resourceType = resourceType;
        }

        /** Backward-compatible constructor (defaults resourceType to 0) */
        public LabBase(String uri, BigInteger price, String accessURI,
                      String accessKey, BigInteger createdAt) {
            this(uri, price, accessURI, accessKey, createdAt, BigInteger.ZERO);
        }
    }
    
    // Lab struct - Simple POJO
    public static class Lab {
        public BigInteger labId;
        public LabBase base;
        
        public Lab(BigInteger labId, LabBase base) {
            this.labId = labId;
            this.base = base;
        }
    }

    /**
     * Register a schacHomeOrganization for the calling provider (InstitutionalOrgRegistryFacet)
     */
    public RemoteFunctionCall<TransactionReceipt> registerSchacHomeOrganization(String organization) {
        final Function function = new Function(
            "registerSchacHomeOrganization",
            Arrays.asList(new Utf8String(organization)),
            List.of()
        );
        return executeRemoteCallTransaction(function);
    }

    /**
     * Set the backend URL for a schacHomeOrganization (InstitutionalOrgRegistryFacet)
     */
    public RemoteFunctionCall<TransactionReceipt> setSchacHomeOrganizationBackend(String organization, String backendUrl) {
        final Function function = new Function(
            "setSchacHomeOrganizationBackend",
            Arrays.asList(new Utf8String(organization), new Utf8String(backendUrl)),
            List.of()
        );
        return executeRemoteCallTransaction(function);
    }

    /**
     * Admin helper to set a backend URL for an organization (InstitutionalOrgRegistryFacet)
     */
    public RemoteFunctionCall<TransactionReceipt> adminSetSchacHomeOrganizationBackend(
        String provider,
        String organization,
        String backendUrl
    ) {
        final Function function = new Function(
            "adminSetSchacHomeOrganizationBackend",
            Arrays.asList(new Address(provider), new Utf8String(organization), new Utf8String(backendUrl)),
            List.of()
        );
        return executeRemoteCallTransaction(function);
    }

    /**
     * Get the backend URL for a schacHomeOrganization (InstitutionalOrgRegistryFacet)
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<String> getSchacHomeOrganizationBackend(String organization) {
        final Function function = new Function(
            "getSchacHomeOrganizationBackend",
            Arrays.asList(new Utf8String(organization)),
            Arrays.asList(new TypeReference<Utf8String>() {})
        );
        return new RemoteFunctionCall<>(function,
            () -> {
                Type result = executeCallSingleValueReturn(function);
                return (String) result.getValue();
            });
    }

    /**
     * Admin helper to grant institution role and register an organization (InstitutionFacet)
     */
    public RemoteFunctionCall<TransactionReceipt> grantInstitutionRole(String institution, String organization) {
        final Function function = new Function(
            "grantInstitutionRole",
            Arrays.asList(new Address(institution), new Utf8String(organization)),
            List.of()
        );
        return executeRemoteCallTransaction(function);
    }
    
    /**
     * Get reservation by key (ReservationFacet)
     * Returns Reservation struct (6 fields)
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<Reservation> getReservation(byte[] reservationKey) {
        final Function function = new Function("getReservation",
                Arrays.asList(new Bytes32(reservationKey)),
                Arrays.asList(
                    new TypeReference<Uint256>() {},
                    new TypeReference<Address>() {},
                    new TypeReference<Uint96>() {},
                    new TypeReference<Address>() {},
                    new TypeReference<Uint8>() {},
                    new TypeReference<Uint32>() {},
                    new TypeReference<Uint32>() {},
                    new TypeReference<Uint64>() {},
                    new TypeReference<Uint64>() {},
                    new TypeReference<Address>() {},
                    new TypeReference<Address>() {},
                    new TypeReference<Uint96>() {}
                ));
        return new RemoteFunctionCall<>(function,
                () -> {
                    List<Type> results = executeCallMultipleValueReturn(function);
                    return new Reservation(
                        ((Uint256) results.get(0)).getValue(),
                        ((Address) results.get(1)).getValue(),
                        ((Uint96) results.get(2)).getValue(),
                        ((Address) results.get(3)).getValue(),
                        ((Uint8) results.get(4)).getValue(),
                        ((Uint32) results.get(5)).getValue(),
                        ((Uint32) results.get(6)).getValue(),
                        ((Uint64) results.get(7)).getValue(),
                        ((Uint64) results.get(8)).getValue(),
                        ((Address) results.get(9)).getValue(),
                        ((Address) results.get(10)).getValue(),
                        ((Uint96) results.get(11)).getValue()
                    );
                });
    }

    /**
     * Get reservation PUC hash by key (bytes32).
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<byte[]> getReservationPucHash(byte[] reservationKey) {
        final Function function = new Function("getReservationPucHash",
                Arrays.asList(new Bytes32(reservationKey)),
                Arrays.asList(new TypeReference<Bytes32>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    Type result = executeCallSingleValueReturn(function);
                    return (byte[]) result.getValue();
                });
    }

    /**
     * Get creator PUC hash by lab id (bytes32).
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<byte[]> getCreatorPucHash(BigInteger labId) {
        final Function function = new Function("getCreatorPucHash",
                Arrays.asList(new Uint256(labId)),
                Arrays.asList(new TypeReference<Bytes32>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    Type result = executeCallSingleValueReturn(function);
                    return (byte[]) result.getValue();
                });
    }
    
    /**
     * Find reservation key for a specific lab token at a given timestamp (ReservationStatsFacet).
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<BigInteger[]> findReservationAt(BigInteger tokenId, BigInteger timestamp) {
        final Function function = new Function("findReservationAt",
                Arrays.asList(new Uint256(tokenId), new Uint32(timestamp)),
                Arrays.asList(new TypeReference<Uint32>() {}, new TypeReference<Uint32>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    List<Type> results = executeCallMultipleValueReturn(function);
                    return new BigInteger[] {
                        ((Uint32) results.get(0)).getValue(),
                        ((Uint32) results.get(1)).getValue()
                    };
                });
    }

    /**
     * Get the total number of reservations for a wallet address (ReservationStatsFacet).
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<BigInteger> reservationsOf(String user) {
        final Function function = new Function("reservationsOf",
                Arrays.asList(new Address(user)),
                Arrays.asList(new TypeReference<Uint256>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    Type result = executeCallSingleValueReturn(function);
                    return (BigInteger) result.getValue();
                });
    }

    /**
     * Get reservation key at a specific index for a wallet address (ReservationStatsFacet).
     * Order is NOT stable across mutations — use for snapshot iteration only.
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<byte[]> reservationKeyOfUserByIndex(String user, BigInteger index) {
        final Function function = new Function("reservationKeyOfUserByIndex",
                Arrays.asList(new Address(user), new Uint256(index)),
                Arrays.asList(new TypeReference<Bytes32>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    Type result = executeCallSingleValueReturn(function);
                    return (byte[]) result.getValue();
                });
    }

    /**
     * Get the active reservation key for a (lab token, wallet) pair (ReservationStatsFacet).
     * O(1) fast path via the dedicated on-chain index; O(≤10) slow path when stale.
     * Returns bytes32(0) when no active reservation exists.
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<byte[]> getActiveReservationKeyForUser(BigInteger tokenId, String user) {
        final Function function = new Function("getActiveReservationKeyForUser",
                Arrays.asList(new Uint256(tokenId), new Address(user)),
                Arrays.asList(new TypeReference<Bytes32>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    Type result = executeCallSingleValueReturn(function);
                    return (byte[]) result.getValue();
                });
    }

    /**
     * Get the total number of reservations for a lab token (InstitutionalReservationQueryFacet).
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<BigInteger> getReservationsOfToken(BigInteger tokenId) {
        final Function function = new Function("getReservationsOfToken",
                Arrays.asList(new Uint256(tokenId)),
                Arrays.asList(new TypeReference<Uint256>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    Type result = executeCallSingleValueReturn(function);
                    return (BigInteger) result.getValue();
                });
    }

    /**
     * Get reservation key at a specific index for a lab token (InstitutionalReservationQueryFacet).
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<byte[]> getReservationOfTokenByIndex(BigInteger tokenId, BigInteger index) {
        final Function function = new Function("getReservationOfTokenByIndex",
                Arrays.asList(new Uint256(tokenId), new Uint256(index)),
                Arrays.asList(new TypeReference<Bytes32>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    Type result = executeCallSingleValueReturn(function);
                    return (byte[]) result.getValue();
                });
    }

    /**
     * Get active reservation key for an institutional user (provider + PUC)
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<byte[]> getInstitutionalUserActiveReservationKey(String provider, String puc, BigInteger tokenId) {
        final Function function = new Function("getInstitutionalUserActiveReservationKey",
                Arrays.asList(new Address(provider), new Utf8String(puc), new Uint256(tokenId)),
                Arrays.asList(new TypeReference<Bytes32>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    Type result = executeCallSingleValueReturn(function);
                    return (byte[]) result.getValue();
                });
    }

    /**
     * Submit an institutional reservation request.
     */
    public RemoteFunctionCall<TransactionReceipt> institutionalReservationRequest(
        String institutionalProvider,
        String puc,
        BigInteger labId,
        BigInteger start,
        BigInteger end
    ) {
        final Function function = new Function("institutionalReservationRequest",
            Arrays.asList(
                new Address(institutionalProvider),
                new Utf8String(puc),
                new Uint256(labId),
                new Uint32(start),
                new Uint32(end)
            ),
            List.of()
        );
        return executeRemoteCallTransaction(function);
    }

    /**
     * Confirm an institutional reservation request with PUC.
     */
    public RemoteFunctionCall<TransactionReceipt> confirmInstitutionalReservationRequestWithPuc(
        String institutionalProvider,
        byte[] reservationKey,
        String puc
    ) {
        final Function function = new Function(
            "confirmInstitutionalReservationRequestWithPuc",
            Arrays.asList(new Address(institutionalProvider), new Bytes32(reservationKey), new Utf8String(puc)),
            List.of()
        );
        return executeRemoteCallTransaction(function);
    }

    /**
     * Confirm a pending reservation request.
     */
    public RemoteFunctionCall<TransactionReceipt> confirmReservationRequest(byte[] reservationKey) {
        final Function function = new Function(
            "confirmReservationRequest",
            Arrays.asList(new Bytes32(reservationKey)),
            List.of()
        );
        return executeRemoteCallTransaction(function);
    }

    /**
     * Cancel an institutional booking with PUC.
     */
    public RemoteFunctionCall<TransactionReceipt> cancelInstitutionalBookingWithPuc(
        String institutionalProvider,
        byte[] reservationKey,
        String puc
    ) {
        final Function function = new Function(
            "cancelInstitutionalBookingWithPuc",
            Arrays.asList(new Address(institutionalProvider), new Bytes32(reservationKey), new Utf8String(puc)),
            List.of()
        );
        return executeRemoteCallTransaction(function);
    }

    /**
     * Deny a pending reservation request.
     */
    public RemoteFunctionCall<TransactionReceipt> denyReservationRequest(byte[] reservationKey) {
        final Function function = new Function(
            "denyReservationRequest",
            Arrays.asList(new Bytes32(reservationKey)),
            List.of()
        );
        return executeRemoteCallTransaction(function);
    }

    /**
     * Get the authentication URI for a provider
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<String> getProviderAuthURI(String provider) {
        final Function function = new Function("getProviderAuthURI",
                Arrays.asList(new Address(provider)),
                Arrays.asList(new TypeReference<Utf8String>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    Type result = executeCallSingleValueReturn(function);
                    return (String) result.getValue();
                });
    }
    
    /**
     * Get lab information (LabFacet)
     * Manual ABI decoding for nested struct:
     * Lab(uint256, LabBase(string, uint96, string, string, uint32, uint8))
     * 
     * Solidity ABI encoding for tuple with dynamic types:
     * - offset_0: labId (uint256) - 32 bytes
     * - offset_32: pointer to LabBase tuple start - 32 bytes  
     * - offset_64+: LabBase tuple data with offsets for strings
     */
    public RemoteFunctionCall<Lab> getLab(BigInteger tokenId) {
        final Function function = new Function("getLab",
                Arrays.asList(new Uint256(tokenId)),
                java.util.Collections.emptyList());
        
        return new RemoteFunctionCall<Lab>(function,
                () -> {
                    String encodedFunction = FunctionEncoder.encode(function);
                    org.web3j.protocol.core.methods.response.EthCall response = web3j.ethCall(
                        org.web3j.protocol.core.methods.request.Transaction.createEthCallTransaction(
                            null, contractAddress, encodedFunction),
                        org.web3j.protocol.core.DefaultBlockParameterName.LATEST
                    ).send();
                    
                    String hex = response.getValue();
                    if (hex == null || hex.isBlank() || "0x".equalsIgnoreCase(hex)) {
                        throw new IllegalStateException("Empty response decoding getLab(" + tokenId + ")");
                    }
                    if (hex.startsWith("0x") || hex.startsWith("0X")) {
                        hex = hex.substring(2);
                    }

                    // Some providers encode single tuple returns with an initial offset, others return tuple head directly.
                    // Try the offset form first, then fallback to direct tuple decoding.
                    int candidateTupleOffset = 0;
                    try {
                        candidateTupleOffset = parseOffsetWordChars(hex, 0, "tuple offset");
                    } catch (IllegalArgumentException ignored) {
                        candidateTupleOffset = 0;
                    }

                    IllegalArgumentException firstFailure = null;
                    int[] attempts = candidateTupleOffset == 0 ? new int[] {0} : new int[] {candidateTupleOffset, 0};
                    for (int tupleOffset : attempts) {
                        try {
                            return decodeLabAtOffset(hex, tupleOffset, tokenId);
                        } catch (IllegalArgumentException ex) {
                            if (firstFailure == null) {
                                firstFailure = ex;
                            } else {
                                firstFailure.addSuppressed(ex);
                            }
                        }
                    }

                    throw new IllegalStateException("Unable to decode getLab(" + tokenId + ") response", firstFailure);
                });
    }
    
    private Lab decodeLabAtOffset(String hex, int tupleOffset, BigInteger expectedLabId) {
        if (tupleOffset < 0 || tupleOffset % 64 != 0) {
            throw new IllegalArgumentException("Invalid tuple offset (chars): " + tupleOffset);
        }
        if (tupleOffset + 128 > hex.length()) {
            throw new IllegalArgumentException("Tuple header out of bounds at offset " + tupleOffset);
        }

        BigInteger labId = parseWordAsBigInteger(hex, tupleOffset, "labId");
        int labBaseOffsetRelative = parseOffsetWordChars(hex, tupleOffset + 64, "labBase offset");
        int labBaseStart;
        try {
            labBaseStart = Math.addExact(tupleOffset, labBaseOffsetRelative);
        } catch (ArithmeticException ex) {
            throw new IllegalArgumentException("labBase absolute offset overflow", ex);
        }

        if (labBaseStart < 0 || labBaseStart + 384 > hex.length()) {
            throw new IllegalArgumentException("LabBase header out of bounds at offset " + labBaseStart);
        }

        int uriOffsetRel = parseOffsetWordChars(hex, labBaseStart, "uri offset");
        BigInteger price = parseWordAsBigInteger(hex, labBaseStart + 64, "price");
        int accessURIOffsetRel = parseOffsetWordChars(hex, labBaseStart + 128, "accessURI offset");
        int accessKeyOffsetRel = parseOffsetWordChars(hex, labBaseStart + 192, "accessKey offset");
        BigInteger createdAt = parseWordAsBigInteger(hex, labBaseStart + 256, "createdAt");
        BigInteger resourceType = parseWordAsBigInteger(hex, labBaseStart + 320, "resourceType");

        String uri = decodeString(hex, addChecked(labBaseStart, uriOffsetRel), "uri");
        String accessURI = decodeString(hex, addChecked(labBaseStart, accessURIOffsetRel), "accessURI");
        String accessKey = decodeString(hex, addChecked(labBaseStart, accessKeyOffsetRel), "accessKey");

        if (expectedLabId != null && !expectedLabId.equals(labId)) {
            throw new IllegalArgumentException(
                "Decoded labId " + labId + " does not match expected " + expectedLabId
            );
        }

        LabBase base = new LabBase(uri, price, accessURI, accessKey, createdAt, resourceType);
        return new Lab(labId, base);
    }

    private String decodeString(String hex, int offset, String fieldName) {
        int length = parseWordAsInt(hex, offset, fieldName + " length");
        if (length == 0) {
            return "";
        }

        int dataStart = addChecked(offset, 64);
        long dataEndLong = (long) dataStart + ((long) length * 2L);
        if (dataEndLong > hex.length()) {
            throw new IllegalArgumentException(fieldName + " data out of bounds");
        }
        String hexData = hex.substring(dataStart, (int) dataEndLong);
        byte[] bytes = org.web3j.utils.Numeric.hexStringToByteArray(hexData);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    private int parseOffsetWordChars(String hex, int wordOffsetChars, String label) {
        BigInteger byteOffset = parseWordAsBigInteger(hex, wordOffsetChars, label);
        if (byteOffset.signum() < 0) {
            throw new IllegalArgumentException(label + " cannot be negative");
        }
        BigInteger charOffset = byteOffset.multiply(BigInteger.TWO);
        if (charOffset.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0) {
            throw new IllegalArgumentException(label + " is too large: " + byteOffset);
        }
        return charOffset.intValue();
    }

    private int parseWordAsInt(String hex, int wordOffsetChars, String label) {
        BigInteger value = parseWordAsBigInteger(hex, wordOffsetChars, label);
        if (value.signum() < 0 || value.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0) {
            throw new IllegalArgumentException(label + " is out of int range: " + value);
        }
        return value.intValue();
    }

    private BigInteger parseWordAsBigInteger(String hex, int wordOffsetChars, String label) {
        String word = sliceWord(hex, wordOffsetChars, label);
        return new BigInteger(word, 16);
    }

    private String sliceWord(String hex, int wordOffsetChars, String label) {
        int end;
        try {
            end = Math.addExact(wordOffsetChars, 64);
        } catch (ArithmeticException ex) {
            throw new IllegalArgumentException(label + " offset overflow", ex);
        }
        if (wordOffsetChars < 0 || end > hex.length()) {
            throw new IllegalArgumentException(label + " word out of bounds at offset " + wordOffsetChars);
        }
        return hex.substring(wordOffsetChars, end);
    }

    private int addChecked(int a, int b) {
        try {
            return Math.addExact(a, b);
        } catch (ArithmeticException ex) {
            throw new IllegalArgumentException("Offset overflow: " + a + " + " + b, ex);
        }
    }

    public static Function authorizeBackendFunction(String backendAddress) {
        return new Function(
            "authorizeBackend",
            Arrays.asList(new Address(backendAddress)),
            List.of()
        );
    }

    public static Function revokeBackendFunction() {
        return new Function(
            "revokeBackend",
            List.of(),
            List.of()
        );
    }

    public static Function adminResetBackendFunction(String providerAddress, String backendAddress) {
        return new Function(
            "adminResetBackend",
            Arrays.asList(new Address(providerAddress), new Address(backendAddress)),
            List.of()
        );
    }

    public static Function setInstitutionalUserLimitFunction(BigInteger limit) {
        return new Function(
            "setInstitutionalUserLimit",
            Arrays.asList(new Uint256(limit)),
            List.of()
        );
    }

    public static Function setInstitutionalSpendingPeriodFunction(BigInteger period) {
        return new Function(
            "setInstitutionalSpendingPeriod",
            Arrays.asList(new Uint256(period)),
            List.of()
        );
    }

    public static Function resetInstitutionalSpendingPeriodFunction() {
        return new Function(
            "resetInstitutionalSpendingPeriod",
            List.of(),
            List.of()
        );
    }

    public static Function issueServiceCreditsFunction(String creditAccount, BigInteger amount, byte[] reference) {
        return new Function(
            "issueServiceCredits",
            Arrays.asList(
                new Address(creditAccount),
                new Uint256(amount),
                new Bytes32(reference)
            ),
            List.of()
        );
    }

    public static Function adjustServiceCreditsFunction(String creditAccount, BigInteger delta, byte[] reference) {
        return new Function(
            "adjustServiceCredits",
            Arrays.asList(
                new Address(creditAccount),
                new org.web3j.abi.datatypes.generated.Int256(delta),
                new Bytes32(reference)
            ),
            List.of()
        );
    }

    public static Function requestProviderPayoutFunction(BigInteger labId, BigInteger maxBatch) {
        return new Function(
            "requestProviderPayout",
            Arrays.asList(new Uint256(labId), new Uint256(maxBatch)),
            List.of()
        );
    }

    public static Function transitionProviderReceivableStateFunction(
        BigInteger labId,
        BigInteger fromState,
        BigInteger toState,
        BigInteger amount,
        byte[] reference
    ) {
        // fromState and toState are uint8 in the ABI: transitionProviderReceivableState(uint256,uint8,uint8,uint256,bytes32)
        // Using Uint256 here would produce a different function selector and the call would always revert.
        return new Function(
            "transitionProviderReceivableState",
            Arrays.asList(
                new Uint256(labId),
                new Uint8(fromState.longValue()),
                new Uint8(toState.longValue()),
                new Uint256(amount),
                new Bytes32(reference)
            ),
            List.of()
        );
    }
    
    /**
     * Load an existing Diamond contract
     */
    public static Diamond load(String contractAddress, Web3j web3j,
                               TransactionManager transactionManager,
                               ContractGasProvider contractGasProvider) {
        return new Diamond(contractAddress, web3j, transactionManager, contractGasProvider);
    }
    
    /**
     * Load an existing Diamond contract with credentials
     */
    public static Diamond load(String contractAddress, Web3j web3j,
                               Credentials credentials,
                               ContractGasProvider contractGasProvider) {
        return new Diamond(contractAddress, web3j, credentials, contractGasProvider);
    }
}
