package decentralabs.blockchain.dto.health;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PeriodRules {
    private String startGranularity;
    private Integer minimumNoticeHours;
    private Boolean allowCustomDateRange;
    private Integer minDurationDays;
    private Integer maxDurationDays;
    private Boolean enforceDailyWindow;
}
