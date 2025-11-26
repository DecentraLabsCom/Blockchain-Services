package decentralabs.blockchain.dto.health;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Represents a maintenance window when the lab is unavailable
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MaintenanceWindow {
    private Instant start;
    private Instant end;
    private String reason;
}
