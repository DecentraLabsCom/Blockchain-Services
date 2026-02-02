package decentralabs.blockchain.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;

/**
 * Lightweight JSON HttpMessageConverter using Jackson ObjectMapper.
 * This avoids relying on deprecated Spring-provided implementation.
 */
public class JacksonHttpMessageConverter implements HttpMessageConverter<Object> {

    private final ObjectMapper objectMapper;

    public JacksonHttpMessageConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean canRead(Class<?> clazz, MediaType mediaType) {
        return canReadOrWrite(mediaType);
    }

    @Override
    public boolean canWrite(Class<?> clazz, MediaType mediaType) {
        return canReadOrWrite(mediaType);
    }

    private boolean canReadOrWrite(MediaType mediaType) {
        if (mediaType == null) return true;
        return MediaType.APPLICATION_JSON.isCompatibleWith(mediaType);
    }

    @Override
    public List<MediaType> getSupportedMediaTypes() {
        return Collections.singletonList(MediaType.APPLICATION_JSON);
    }

    @Override
    public Object read(Class<? extends Object> clazz, HttpInputMessage inputMessage) throws IOException {
        return objectMapper.readValue(inputMessage.getBody(), clazz);
    }

    @Override
    public void write(Object t, MediaType contentType, HttpOutputMessage outputMessage) throws IOException {
        outputMessage.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        outputMessage.getHeaders().setAcceptCharset(Collections.singletonList(StandardCharsets.UTF_8));
        objectMapper.writeValue(outputMessage.getBody(), t);
    }
}
