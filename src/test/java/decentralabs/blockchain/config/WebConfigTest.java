package decentralabs.blockchain.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping;
import org.springframework.web.servlet.mvc.ParameterizableViewController;

class WebConfigTest {

    private final WebConfig config = new WebConfig();

    @Test
    void restTemplate_returnsConcreteBean() {
        assertThat(config.restTemplate()).isInstanceOf(RestTemplate.class);
    }

    @Test
    void objectMapper_disablesTimestampDates() {
        ObjectMapper mapper = config.objectMapper();

        assertThat(mapper.isEnabled(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)).isFalse();
    }

    @Test
    void jacksonHttpMessageConverter_usesProvidedObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();

        JacksonHttpMessageConverter converter = config.jacksonHttpMessageConverter(mapper);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpOutputMessage outputMessage = new HttpOutputMessage() {
            private final HttpHeaders headers = new HttpHeaders();

            @Override
            public HttpHeaders getHeaders() {
                return headers;
            }

            @Override
            public ByteArrayOutputStream getBody() {
                return body;
            }
        };

        assertThatCode(() -> converter.write(Map.of("ok", true), MediaType.APPLICATION_JSON, outputMessage))
            .doesNotThrowAnyException();
        assertThat(body.toString(StandardCharsets.UTF_8)).contains("\"ok\":true");
    }

    @Test
    void addViewControllers_registersExpectedRedirectsAndForwards() throws Exception {
        StaticApplicationContext applicationContext = new StaticApplicationContext();
        TestViewControllerRegistry registry = new TestViewControllerRegistry(applicationContext);

        config.addViewControllers(registry);

        SimpleUrlHandlerMapping mapping = registry.exposeHandlerMapping();
        mapping.setApplicationContext(applicationContext);
        mapping.initApplicationContext();

        Map<String, String> expectedViews = Map.of(
            "/", "redirect:/wallet-dashboard/",
            "/wallet-dashboard", "redirect:/wallet-dashboard/",
            "/wallet-dashboard/", "forward:/wallet-dashboard/index.html",
            "/institution-config", "redirect:/institution-config/",
            "/institution-config/", "forward:/institution-config/index.html"
        );

        for (Map.Entry<String, String> entry : expectedViews.entrySet()) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", entry.getKey());
            HandlerExecutionChain chain = mapping.getHandler(request);

            assertThat(chain).isNotNull();
            assertThat(chain.getHandler()).isInstanceOf(ParameterizableViewController.class);
            assertThat(((ParameterizableViewController) chain.getHandler()).getViewName()).isEqualTo(entry.getValue());
        }
    }

    private static final class TestViewControllerRegistry extends ViewControllerRegistry {

        private TestViewControllerRegistry(StaticApplicationContext applicationContext) {
            super(applicationContext);
        }

        private SimpleUrlHandlerMapping exposeHandlerMapping() {
            return super.buildHandlerMapping();
        }
    }
}
