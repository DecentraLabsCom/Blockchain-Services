package decentralabs.blockchain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EventListenerRequest {
    private String contractAddress;
    private String eventName;
    private List<String> topics; // optional for filtering
}