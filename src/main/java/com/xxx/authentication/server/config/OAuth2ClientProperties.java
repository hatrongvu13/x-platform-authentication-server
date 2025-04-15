package com.xxx.authentication.server.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "oauth2")
@Component
@Data
public class OAuth2ClientProperties {
    private List<Client> clients = new ArrayList<>();

    public List<Client> getClients() {
        return clients;
    }

    @Data
    public static class Client {
        private String clientId;
        private String clientSecret;
        private List<String> grantTypes;
        private List<String> scopes;
    }
}
