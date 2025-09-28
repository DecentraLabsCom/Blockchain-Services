/*package decentralabs.auth.listener;

import decentralabs.auth.ReservationContract;

import org.springframework.stereotype.Component;

import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.ClientTransactionManager;
import org.web3j.tx.gas.DefaultGasProvider;

import java.math.BigInteger;

@Value("${contract.address}")
private String contractAddress;
@Value("${rpc.url}")
private String rpcUrl;
@Value("${wallet.address}")
private String walletAddress;
@Value("${wallet.private.key}")
private String walletPrivateKey;

@Component
public class ReservationEventListener {

    private final Web3j web3j;
    private final ReservationContract contract;

    public ReservationEventListener() {
        this.web3j = Web3j.build(new HttpService(rpcUrl));
        this.contract = ReservationContract.load(
            contractAddress,
            web3j,
            new ClientTransactionManager(web3j, walletAddress),
            new DefaultGasProvider()
        );
        listenToEvents();
    }

    private void listenToEvents() {
        contract.reservationRequestedEventFlowable(DefaultBlockParameterName.EARLIEST, 
        DefaultBlockParameterName.LATEST)
            .subscribe(event -> {
                // Extract event data
                String user = event.user;
                BigInteger labId = event.labId;

                System.out.println("Detected event: User " + user + ", Lab ID " + labId);

                // TODO - Fetch booking configuration from metadata file
                // TODO - Check if the requested date and time are valid

                // Execute transaction to call confirmReservationRequest
                try {
                    contract.confirmReservationRequest(user, labId).send();
                    System.out.println("Reservation confirmed for " + user + " and Lab ID " + labId);
                } catch (Exception e) {
                    System.err.println("Error while confirming a reservation: " + e.getMessage());
                }
            });
    }
            
}*/
