package decentralabs.blockchain.controller.intent;

import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentStatusResponse;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.service.intent.IntentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("${endpoint.intents:/intents}")
@RequiredArgsConstructor
@Slf4j
public class IntentController {

    private final IntentService intentService;

    @Value("${intents.api-key:}")
    private String configuredApiKey;

    @PostMapping
    public ResponseEntity<IntentAckResponse> submitIntent(
        @RequestBody @Valid IntentSubmission submission,
        @RequestHeader(value = "x-api-key", required = false) String apiKeyHeader,
        @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        enforceApiKey(apiKeyHeader, authorizationHeader);
        IntentAckResponse ack = intentService.processIntent(submission);
        log.info("Intent {} ACK status={}", ack.getRequestId(), ack.getStatus());
        return ResponseEntity.ok(ack);
    }

    @GetMapping("/{requestId}")
    public ResponseEntity<IntentStatusResponse> getIntentStatus(
        @PathVariable String requestId,
        @RequestHeader(value = "x-api-key", required = false) String apiKeyHeader,
        @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        enforceApiKey(apiKeyHeader, authorizationHeader);
        return ResponseEntity.ok(intentService.getStatus(requestId));
    }

    private void enforceApiKey(String apiKeyHeader, String authorizationHeader) {
        if (configuredApiKey == null || configuredApiKey.isBlank()) {
            return;
        }
        boolean headerMatch = configuredApiKey.equals(apiKeyHeader);
        boolean bearerMatch = false;
        if (authorizationHeader != null && authorizationHeader.toLowerCase().startsWith("bearer ")) {
            String bearerValue = authorizationHeader.substring("bearer ".length()).trim();
            bearerMatch = configuredApiKey.equals(bearerValue);
        }
        if (!headerMatch && !bearerMatch) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid API key");
        }
    }
}
