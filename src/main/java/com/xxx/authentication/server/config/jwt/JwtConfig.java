package com.xxx.authentication.server.config.jwt;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.xxx.authentication.server.config.properties.OAuth2ClientProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
@RequiredArgsConstructor
public class JwtConfig {
    @Value("${spring.security.jwt.key.private}")
    private Resource privateKeyFile;
    @Value("${spring.security.jwt.key.public}")
    private Resource publicKeyFile;

    private final OAuth2ClientProperties properties;

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAPrivateKey privateKey = readPrivateKey(privateKeyFile.getInputStream());
        RSAPublicKey publicKey = readPublicKey(publicKeyFile.getInputStream());

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(properties.getSecret())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private RSAPrivateKey readPrivateKey(InputStream inputStream) throws Exception {
        String key = new String(inputStream.readAllBytes())
                .replaceAll("-----\\w+ PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    private RSAPublicKey readPublicKey(InputStream inputStream) throws Exception {
        String key = new String(inputStream.readAllBytes())
                .replaceAll("-----\\w+ PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decoded));
    }

    // gen rsa dynamic
    private static KeyPair generateRsaKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
