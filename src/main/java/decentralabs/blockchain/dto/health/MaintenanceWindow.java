package decentralabs.blockchain.dto.health;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Represents a maintenance window when the lab is unavailable
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MaintenanceWindow {
    private LocalDateTime start;
    private LocalDateTime end;
    private String reason;
}
