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
            String collectorInstitution
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
        }
    }
    
    // LabBase struct - Simple POJO
    public static class LabBase {
        public String uri;        // metadata URI
        public BigInteger price;  // uint96 in Solidity
        public String auth;       // auth URI
        public String accessURI;  // access URI
        public String accessKey;  // access key
        
        public LabBase(String uri, BigInteger price, String auth, 
                      String accessURI, String accessKey) {
            this.uri = uri;
            this.price = price;
            this.auth = auth;
            this.accessURI = accessURI;
            this.accessKey = accessKey;
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
                    new TypeReference<Address>() {}
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
                        ((Address) results.get(11)).getValue()
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
     * Get lab information (LabFacet)
     * Manual ABI decoding for nested struct: Lab(uint256, LabBase(string, uint96, string, string, string))
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
                    // LabBase structure: (string uri, uint96 price, string auth, string accessURI, string accessKey)
                    // Word 0: offset to uri (relative to LabBase start)
                    // Word 1: price (uint96, right-aligned in 32 bytes)
                    // Word 2: offset to auth
                    // Word 3: offset to accessURI  
                    // Word 4: offset to accessKey
                    // Word 5+: actual string data
                    
                    int uriOffsetRel = new BigInteger(hex.substring(labBaseStart, labBaseStart + 64), 16).intValue() * 2;
                    BigInteger price = new BigInteger(hex.substring(labBaseStart + 64, labBaseStart + 128), 16);
                    int authOffsetRel = new BigInteger(hex.substring(labBaseStart + 128, labBaseStart + 192), 16).intValue() * 2;
                    int accessURIOffsetRel = new BigInteger(hex.substring(labBaseStart + 192, labBaseStart + 256), 16).intValue() * 2;
                    int accessKeyOffsetRel = new BigInteger(hex.substring(labBaseStart + 256, labBaseStart + 320), 16).intValue() * 2;
                    
                    // Decode strings (offsets are relative to LabBase start)
                    String uri = decodeString(hex, labBaseStart + uriOffsetRel);
                    String auth = decodeString(hex, labBaseStart + authOffsetRel);
                    String accessURI = decodeString(hex, labBaseStart + accessURIOffsetRel);
                    String accessKey = decodeString(hex, labBaseStart + accessKeyOffsetRel);
                    
                    LabBase base = new LabBase(uri, price, auth, accessURI, accessKey);
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
