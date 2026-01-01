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
    public static class Reservation {
        public BigInteger labId;               // uint256 - lab token ID
        public String renter;                  // address
        public BigInteger price;               // uint96 - reservation price
        public String labProvider;             // address
        public BigInteger status;              // uint8 - reservation status
        public BigInteger start;               // uint32 - start timestamp
        public BigInteger end;                 // uint32 - end timestamp
        public String puc;                     // string - institutional identifier (empty for wallet)
        public BigInteger requestPeriodStart;  // uint64 - institutional request window start
        public BigInteger requestPeriodDuration; // uint64 - institutional request window duration
        public String payerInstitution;        // address - institution paying for reservation
        public String collectorInstitution;    // address - institution receiving payout
        public BigInteger providerShare;       // uint96 - provider allocation
        public BigInteger projectTreasuryShare; // uint96 - project treasury allocation
        public BigInteger subsidiesShare;      // uint96 - subsidies allocation
        public BigInteger governanceShare;     // uint96 - governance allocation

        public Reservation(
            BigInteger labId,
            String renter,
            BigInteger price,
            String labProvider,
            BigInteger status,
            BigInteger start,
            BigInteger end,
            String puc,
            BigInteger requestPeriodStart,
            BigInteger requestPeriodDuration,
            String payerInstitution,
            String collectorInstitution,
            BigInteger providerShare,
            BigInteger projectTreasuryShare,
            BigInteger subsidiesShare,
            BigInteger governanceShare
        ) {
            this.labId = labId;
            this.renter = renter;
            this.price = price;
            this.labProvider = labProvider;
            this.status = status;
            this.start = start;
            this.end = end;
            this.puc = puc;
            this.requestPeriodStart = requestPeriodStart;
            this.requestPeriodDuration = requestPeriodDuration;
            this.payerInstitution = payerInstitution;
            this.collectorInstitution = collectorInstitution;
            this.providerShare = providerShare;
            this.projectTreasuryShare = projectTreasuryShare;
            this.subsidiesShare = subsidiesShare;
            this.governanceShare = governanceShare;
        }
    }
    
    // LabBase struct - Simple POJO
    public static class LabBase {
        public String uri;        // metadata URI
        public BigInteger price;  // uint96 in Solidity
        public String accessURI;  // access URI
        public String accessKey;  // access key
        public BigInteger createdAt; // uint32

        public LabBase(String uri, BigInteger price, String accessURI,
                      String accessKey, BigInteger createdAt) {
            this.uri = uri;
            this.price = price;
            this.accessURI = accessURI;
            this.accessKey = accessKey;
            this.createdAt = createdAt;
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
                    new TypeReference<Utf8String>() {},
                    new TypeReference<Uint64>() {},
                    new TypeReference<Uint64>() {},
                    new TypeReference<Address>() {},
                    new TypeReference<Address>() {},
                    new TypeReference<Uint96>() {},
                    new TypeReference<Uint96>() {},
                    new TypeReference<Uint96>() {},
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
                        ((Utf8String) results.get(7)).getValue(),
                        ((Uint64) results.get(8)).getValue(),
                        ((Uint64) results.get(9)).getValue(),
                        ((Address) results.get(10)).getValue(),
                        ((Address) results.get(11)).getValue(),
                        ((Uint96) results.get(12)).getValue(),
                        ((Uint96) results.get(13)).getValue(),
                        ((Uint96) results.get(14)).getValue(),
                        ((Uint96) results.get(15)).getValue()
                    );
                });
    }
    
    /**
     * Check if user has active booking by token
     */
    @SuppressWarnings("rawtypes")
    public RemoteFunctionCall<Boolean> hasActiveBookingByToken(BigInteger tokenId, String user) {
        final Function function = new Function("hasActiveBookingByToken",
                Arrays.asList(new Uint256(tokenId), new Address(user)),
                Arrays.asList(new TypeReference<org.web3j.abi.datatypes.Bool>() {}));
        return new RemoteFunctionCall<>(function,
                () -> {
                    Type result = executeCallSingleValueReturn(function);
                    return (Boolean) result.getValue();
                });
    }
    
    /**
     * Get active reservation key for user and lab
     * Returns bytes32(0) if no active reservation found
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
     * Get number of reservations for a user
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
     * Get reservation key of user by index
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
     * Manual ABI decoding for nested struct: Lab(uint256, LabBase(string, uint96, string, string, uint32))
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
                    if (hex.startsWith("0x")) hex = hex.substring(2);
                    
                    // ABI encoding for tuple with dynamic fields:
                    // Word 0: offset to actual tuple data
                    // Word offset+0: labId (uint256)
                    // Word offset+1: offset to LabBase (relative to tuple start)
                    // ... LabBase fields follow
                    
                    // Word 0: offset to tuple (usually 0x20 = 32 bytes)
                    int tupleOffset = new BigInteger(hex.substring(0, 64), 16).intValue() * 2;
                    
                    // Read from actual tuple start
                    int pos = tupleOffset;
                    BigInteger labId = new BigInteger(hex.substring(pos, pos + 64), 16);
                    pos += 64;
                    
                    // Next word: offset to LabBase (relative to current position)
                    int labBaseOffsetRelative = new BigInteger(hex.substring(pos, pos + 64), 16).intValue() * 2;
                    pos += 64;
                    
                    // LabBase absolute position
                    int labBaseStart = tupleOffset + labBaseOffsetRelative;
                    
                    // Read LabBase tuple fields
                    // LabBase structure: (string uri, uint96 price, string accessURI, string accessKey, uint32 createdAt)
                    // Word 0: offset to uri (relative to LabBase start)
                    // Word 1: price (uint96, right-aligned in 32 bytes)
                    // Word 2: offset to accessURI
                    // Word 3: offset to accessKey
                    // Word 4: createdAt (uint32, right-aligned in 32 bytes)
                    // Word 5+: actual string data
                    
                    int uriOffsetRel = new BigInteger(hex.substring(labBaseStart, labBaseStart + 64), 16).intValue() * 2;
                    BigInteger price = new BigInteger(hex.substring(labBaseStart + 64, labBaseStart + 128), 16);
                    int accessURIOffsetRel = new BigInteger(hex.substring(labBaseStart + 128, labBaseStart + 192), 16).intValue() * 2;
                    int accessKeyOffsetRel = new BigInteger(hex.substring(labBaseStart + 192, labBaseStart + 256), 16).intValue() * 2;
                    BigInteger createdAt = new BigInteger(hex.substring(labBaseStart + 256, labBaseStart + 320), 16);
                    
                    // Decode strings (offsets are relative to LabBase start)
                    String uri = decodeString(hex, labBaseStart + uriOffsetRel);
                    String accessURI = decodeString(hex, labBaseStart + accessURIOffsetRel);
                    String accessKey = decodeString(hex, labBaseStart + accessKeyOffsetRel);
                    
                    LabBase base = new LabBase(uri, price, accessURI, accessKey, createdAt);
                    return new Lab(labId, base);
                });
    }
    
    private String decodeString(String hex, int offset) {
        int length = new BigInteger(hex.substring(offset, offset + 64), 16).intValue();
        if (length == 0) return "";
        
        String hexData = hex.substring(offset + 64, offset + 64 + (length * 2));
        byte[] bytes = org.web3j.utils.Numeric.hexStringToByteArray(hexData);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
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
