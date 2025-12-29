package decentralabs.blockchain.controller.intent;

import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentStatusResponse;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.service.intent.IntentAuthService;
import decentralabs.blockchain.service.intent.IntentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${endpoint.intents:/intents}")
@RequiredArgsConstructor
@Slf4j
public class IntentController {

    private final IntentService intentService;
    private final IntentAuthService intentAuthService;

    @PostMapping
    public ResponseEntity<IntentAckResponse> submitIntent(
        @RequestBody @Valid IntentSubmission submission,
        @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        intentAuthService.enforceSubmitAuthorization(authorizationHeader);
        IntentAckResponse ack = intentService.processIntent(submission);
        log.info("Intent {} ACK status={}", ack.getRequestId(), ack.getStatus());
        return ResponseEntity.ok(ack);
    }

    @GetMapping("/{requestId}")
    public ResponseEntity<IntentStatusResponse> getIntentStatus(
        @PathVariable String requestId,
        @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        intentAuthService.enforceStatusAuthorization(authorizationHeader);
        return ResponseEntity.ok(intentService.getStatus(requestId));
    }
}
