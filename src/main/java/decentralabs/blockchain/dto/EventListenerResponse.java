package decentralabs.blockchain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EventListenerResponse {
    private boolean success;
    private String contractAddress;
    private String eventName;
    private String network;
    private String message;
    private String error;

    public static EventListenerResponse error(String error) {
        return EventListenerResponse.builder()
            .success(false)
            .error(error)
            .build();
    }
}