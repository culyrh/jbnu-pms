package jbnu.jbnupms.security.oauth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

@Configuration
@RequiredArgsConstructor
public class RestTemplateConfig {

    private final OAuth2Properties oauth2Properties;

    /**
     * 타임아웃 설정이 적용된 RestTemplate Bean
     */
    @Bean
    public RestTemplate oauth2RestTemplate(RestTemplateBuilder builder) {

        return new RestTemplateBuilder()
                .connectTimeout(Duration.ofMillis(oauth2Properties.getRestTemplate().getConnectTimeout())) // setConnectTimeout -> connectTimeout
                .readTimeout(Duration.ofMillis(oauth2Properties.getRestTemplate().getReadTimeout()))       // setReadTimeout -> readTimeout
                .build();
    }
}