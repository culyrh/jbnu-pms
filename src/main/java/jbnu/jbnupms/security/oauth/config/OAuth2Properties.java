package jbnu.jbnupms.security.oauth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "oauth2")
public class OAuth2Properties {

    private Map<String, ProviderConfig> providers = new HashMap<>();
    private RestTemplateConfig restTemplate = new RestTemplateConfig();

    @Getter
    @Setter
    public static class ProviderConfig {
        private String userInfoUri;
        private String userNameAttribute;
    }

    @Getter
    @Setter
    public static class RestTemplateConfig {
        private int connectTimeout = 5000;  // 5초
        private int readTimeout = 10000;     // 10초
    }

    public ProviderConfig getProvider(String providerName) {
        return providers.get(providerName.toLowerCase());
    }
}