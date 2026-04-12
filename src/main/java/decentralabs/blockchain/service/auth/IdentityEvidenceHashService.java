package decentralabs.blockchain.service.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.stereotype.Service;

/**
 * Computes canonical hashes for identity evidence payloads.
 */
@Service
@RequiredArgsConstructor
public class IdentityEvidenceHashService {

    private final ObjectMapper objectMapper;

    /**
     * 
     * @param canonicalEvidence
     * @return
     */
    public String computeCanonicalHash(Object canonicalEvidence) {
        try {
            Object normalized = canonicalize(canonicalEvidence);
            String canonicalJson = objectMapper.writeValueAsString(normalized);
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonicalJson.getBytes(StandardCharsets.UTF_8));
            return "0x" + bytesToHex(digest);
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException("Unable to serialize canonical identity evidence", ex);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to compute canonical identity hash", ex);
        }
    }

    private Object canonicalize(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String || value instanceof Number || value instanceof Boolean) {
            return value;
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                sorted.put(String.valueOf(entry.getKey()), canonicalize(entry.getValue()));
            }
            return sorted;
        }
        if (value instanceof Collection<?> collection) {
            List<Object> items = new ArrayList<>(collection.size());
            for (Object item : collection) {
                items.add(canonicalize(item));
            }
            return items;
        }
        if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            List<Object> items = new ArrayList<>(length);
            for (int i = 0; i < length; i++) {
                items.add(canonicalize(Array.get(value, i)));
            }
            return items;
        }

        Map<String, Object> converted = objectMapper.convertValue(value, LinkedHashMap.class);
        return canonicalize(converted);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }
}
