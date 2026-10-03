package decentralabs.blockchain.service.accesspolicy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AccessPolicyPersistenceService {
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final Map<String, AccessPolicyProfile> memory = new ConcurrentHashMap<>();

    public AccessPolicyPersistenceService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public AccessPolicyProfile find(String institutionId) {
        AccessPolicyProfile cached = memory.get(normalize(institutionId));
        try {
            return jdbcTemplate.query("SELECT * FROM access_policy_profiles WHERE institution_id=? LIMIT 1", (rs, rowNum) -> {
                List<AccessPolicyGroup> groups = readJson(rs.getString("groups_json"), new TypeReference<>() {});
                List<AccessPolicyOverride> overrides = readJson(rs.getString("overrides_json"), new TypeReference<>() {});
                return new AccessPolicyProfile(rs.getString("institution_id"), rs.getString("name"), rs.getInt("version"),
                    rs.getBoolean("enabled"), AccessPolicyDecision.valueOf(rs.getString("default_decision")), groups, overrides);
            }, normalize(institutionId)).stream().findFirst().orElse(cached);
        } catch (Exception ex) {
            return cached;
        }
    }

    public void save(AccessPolicyProfile profile, String actor, String event) {
        memory.put(normalize(profile.institutionId()), profile);
        try {
            jdbcTemplate.update(
                """
                INSERT INTO access_policy_profiles (institution_id,name,version,default_decision,enabled,groups_json,overrides_json,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE name=VALUES(name),version=VALUES(version),default_decision=VALUES(default_decision),
                    enabled=VALUES(enabled),groups_json=VALUES(groups_json),overrides_json=VALUES(overrides_json),updated_at=VALUES(updated_at)
                """,
                profile.institutionId(), profile.name(), profile.version(), profile.defaultDecision().name(), profile.enabled(),
                objectMapper.writeValueAsString(profile.groups()), objectMapper.writeValueAsString(profile.overrides()),
                Timestamp.from(Instant.now()), Timestamp.from(Instant.now())
            );
            jdbcTemplate.update("INSERT INTO access_policy_audit_events (institution_id,policy_version,event_type,actor,details_json,created_at) VALUES (?,?,?,?,?,?)",
                profile.institutionId(), profile.version(), event == null ? "UPDATED" : event, actor,
                objectMapper.writeValueAsString(Map.of("enabled", profile.enabled())), Timestamp.from(Instant.now()));
        } catch (Exception ex) {
            log.warn("Access policy persistence unavailable; retaining in-process policy: {}", ex.getMessage());
        }
    }

    public List<Map<String, Object>> audit(String institutionId, int limit) {
        try {
            return jdbcTemplate.queryForList("SELECT event_type, policy_version, actor, details_json, created_at FROM access_policy_audit_events WHERE institution_id=? ORDER BY created_at DESC LIMIT ?",
                normalize(institutionId), Math.max(1, Math.min(limit, 100)));
        } catch (Exception ex) {
            return List.of();
        }
    }

    private String normalize(String value) { return value == null ? "" : value.trim().toLowerCase(); }

    private <T> T readJson(String value, TypeReference<T> type) {
        try {
            return objectMapper.readValue(value, type);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid access policy JSON", ex);
        }
    }
}
