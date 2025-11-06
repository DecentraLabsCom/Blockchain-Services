package decentralabs.blockchain.config;

import decentralabs.blockchain.service.WalletService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.EthFilter;

import java.util.Arrays;
import java.util.List;

/**
 * Configuration class for setting up contract event listeners on application startup
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ContractEventListenerConfig {

    private final WalletService walletService;

    @Value("${contract.address}")
    private String diamondContractAddress;

    @Value("${contract.events.to.listen:}")
    private String eventsToListen;

    @Value("${contract.event.listening.enabled:true}")
    private boolean eventListeningEnabled;

    @Value("${contract.event.start.block:latest}")
    private String startBlock;

    /**
     * Configure event listeners for Diamond contract on application startup
     */
    @EventListener(ApplicationReadyEvent.class)
    public void configureContractEventListeners() {
        if (!eventListeningEnabled) {
            log.info("Contract event listening is disabled");
            return;
        }

        if (eventsToListen == null || eventsToListen.trim().isEmpty()) {
            log.info("No contract events configured to listen for");
            return;
        }

        log.info("Configuring contract event listeners on startup...");
        log.info("Diamond contract address: {}", diamondContractAddress);
        log.info("Events to listen: {}", eventsToListen);

        // Parse the comma-separated list of events
        List<String> eventList = Arrays.stream(eventsToListen.split(","))
            .map(String::trim)
            .filter(event -> !event.isEmpty())
            .toList();

        if (eventList.isEmpty()) {
            log.warn("No valid events found in configuration");
            return;
        }

        try {
            // Get Web3j instance from WalletService
            Web3j web3j = walletService.getWeb3jInstance();

            // Setup listeners for each event
            for (String eventName : eventList) {
                setupEventListener(web3j, diamondContractAddress, eventName);
            }

            log.info("Contract event listener configuration completed for {} events", eventList.size());

        } catch (Exception e) {
            log.error("Error configuring contract event listeners", e);
        }
    }

    /**
     * Sets up a listener for a specific contract event
     */
    private void setupEventListener(Web3j web3j, String contractAddress, String eventName) {
        try {
            log.info("Setting up listener for event '{}' on contract {}", eventName, contractAddress);

            // Create filter for the contract address
            EthFilter filter = new EthFilter(
                startBlock.equals("latest") ? DefaultBlockParameterName.LATEST : DefaultBlockParameterName.valueOf(startBlock),
                DefaultBlockParameterName.LATEST,
                contractAddress
            );

            // Subscribe to logs (events) from the contract
            web3j.ethLogFlowable(filter).subscribe(
                eventLog -> {
                    log.info("Received {} event from contract {}: {}", eventName, contractAddress, eventLog);
                    // TODO: Process the event data and trigger appropriate actions
                    // For example: update database, send notifications, call webhooks, etc.
                    handleContractEvent(eventName, eventLog);
                },
                error -> log.error("Error listening for {} events: {}", eventName, error.getMessage()),
                () -> log.info("Event listener for {} completed", eventName)
            );

            log.info("Successfully configured listener for {} event", eventName);

        } catch (Exception e) {
            log.error("Failed to setup listener for {} event: {}", eventName, e.getMessage(), e);
        }
    }

    /**
     * Handle incoming contract events
     */
    private void handleContractEvent(String eventName, org.web3j.protocol.core.methods.response.Log eventLog) {
        try {
            log.info("Processing {} event - Transaction: {}, Block: {}",
                    eventName, eventLog.getTransactionHash(), eventLog.getBlockHash());

            // Parse event data based on event type
            switch (eventName) {
                case "ReservationCreated":
                    handleReservationCreated(eventLog);
                    break;
                case "ReservationUpdated":
                    handleReservationUpdated(eventLog);
                    break;
                case "ReservationCancelled":
                    handleReservationCancelled(eventLog);
                    break;
                default:
                    log.warn("Unknown event type: {}", eventName);
            }

        } catch (Exception e) {
            log.error("Error processing {} event: {}", eventName, e.getMessage(), e);
        }
    }

    private void handleReservationCreated(org.web3j.protocol.core.methods.response.Log eventLog) {
        // TODO: Parse event data and handle reservation creation
        // This would involve decoding the event parameters from eventLog.getData() and eventLog.getTopics()
        log.info("Handling ReservationCreated event");
    }

    private void handleReservationUpdated(org.web3j.protocol.core.methods.response.Log eventLog) {
        // TODO: Parse event data and handle reservation update
        log.info("Handling ReservationUpdated event");
    }

    private void handleReservationCancelled(org.web3j.protocol.core.methods.response.Log eventLog) {
        // TODO: Parse event data and handle reservation cancellation
        log.info("Handling ReservationCancelled event");
    }
}