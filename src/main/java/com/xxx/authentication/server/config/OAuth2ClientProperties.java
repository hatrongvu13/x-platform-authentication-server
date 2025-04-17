package com.xxx.authentication.server.config;

import lombok.Data;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Getter
@ConfigurationProperties(prefix = "oauth2")
@Component
@Data
public class OAuth2ClientProperties {
    private List<Client> clients = new ArrayList<>();

    @Data
    public static class Client {
        private String clientId;
        private String clientSecret;
        private List<String> grantTypes;
        private List<String> scopes;
    }
}
