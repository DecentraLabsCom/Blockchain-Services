package decentralabs.blockchain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.DayOfWeek;
import java.time.LocalDate;

/**
 * Represents a maintenance window when the lab is unavailable
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MaintenanceWindow {
    private LocalDate date;
    private DayOfWeek dayOfWeek;
    private TimeRange timeRange;
    private String reason;
}