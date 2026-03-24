package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

/**
 * Rolling offer-volume snapshot for MiCA Art 4(3) compliance monitoring.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MicaOfferVolume {

    private Long id;
    private LocalDate periodStart;
    private LocalDate periodEnd;
    private BigDecimal eurVolume;
    private BigDecimal creditVolume;
    private int transactionCount;
    private Instant computedAt;
}
