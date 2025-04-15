package com.xxx.authentication.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
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
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    @Bean
//    @Order(1)
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
//        http.securityMatcher("/oauth2/**", "/.well-known/**", "/oidc/**") // Chỉ áp dụng cho các endpoint OAuth2
//                .with(authorizationServerConfigurer, authConfigurer ->
//                        authConfigurer
//                                .oidc(Customizer.withDefaults()) // Kích hoạt OIDC
//                                .authorizationEndpoint(Customizer.withDefaults())
//                                .tokenEndpoint(Customizer.withDefaults())
//                )
//                .exceptionHandling(exceptions -> exceptions
//                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//                )
//                .csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**", "/oidc/**"));
//        return http.build();
//    }
//
//    @Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/login").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .formLogin(form -> form.loginPage("/login").permitAll());
//        return http.build();
//    }
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//        var user = User.withUsername("user")
//                .password("{noop}password")
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }
//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        // Client cho Authorization Code
//        RegisteredClient webClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("web-client")
//                .clientSecret("{noop}web-secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("http://localhost:8080/login/oauth2/code/web-client")
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
//                .scope("api.read")
//                .build();
//
//        // Client cho Client Credentials
//        RegisteredClient serviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("service-client")
//                .clientSecret("{noop}service-secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .scope("api.read")
//                .build();
//
//        return new InMemoryRegisteredClientRepository(webClient, serviceClient);
//    }
//
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() throws Exception {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return new ImmutableJWKSet(jwkSet);
//    }
//
//    private static KeyPair generateRsaKey() throws Exception {
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048);
//        return keyPairGenerator.generateKeyPair();
//    }
//}

@Configuration
@EnableWebSecurity
public class SecurityConfig {

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
        RegisteredClient webClient = RegisteredClient.withId("web-client-id")
                .clientId("web-client")
                .clientSecret("{noop}web-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("api.read")
                .build();

        RegisteredClient serviceClient = RegisteredClient.withId("service-client-id")
                .clientId("service-client")
                .clientSecret("{noop}service-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("api.read")
                .build();

        System.out.println("Registered web-client: redirectUri=" + webClient.getRedirectUris() + ", scopes=" + webClient.getScopes());
        return new InMemoryRegisteredClientRepository(webClient, serviceClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("auth-server-key")
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet(jwkSet);
    }

    private static KeyPair generateRsaKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}