package com.xxx.authentication.server.config.security;
import com.xxx.authentication.server.config.properties.OAuth2ClientProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final OAuth2ClientProperties properties;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http
                .securityMatcher("/oauth2/**", "/.well-known/**", "/oidc/**", "/login", "/error")
                .with(authorizationServerConfigurer, authConfigurer ->
                        authConfigurer
                                .oidc(Customizer.withDefaults())
                                .authorizationEndpoint(Customizer.withDefaults())
                                .tokenEndpoint(Customizer.withDefaults())
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/error"),
                                request -> request.getRequestURI().startsWith("/oauth2/authorize")
                        ) // Trang lỗi tùy chỉnh cho /oauth2/authorize
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/oauth2/**", "/.well-known/**", "/oidc/**")
                );
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/error").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/oauth2/authorize", false)
                        .permitAll()
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var user = User.withUsername("user")
                .password("{noop}password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        List<RegisteredClient> clients = properties.getClients().stream()
                .map(prop -> {
                    RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                            .clientId(prop.getClientId())
                            .clientSecret("{noop}" + prop.getClientSecret())
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

                    prop.getGrantTypes().forEach(grant -> {
                        switch (grant) {
                            case "client_credentials" ->
                                    builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
                            case "authorization_code" ->
                                    builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                            case "refresh_token" ->
                                    builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
                            case "password" -> builder.authorizationGrantType(new AuthorizationGrantType("password"));
                            // Add other cases if needed
                        }
                    });

                    prop.getScopes().forEach(builder::scope);
                    return builder.build();
                })
                .toList();
        return new InMemoryRegisteredClientRepository(clients);
    }

}