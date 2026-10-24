package com.eduaircontrol.mssecurity.infrastructure.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

class GoogleIdTokenVerifierTest {

    private static final String CLIENT_ID = "client-123.apps.googleusercontent.com";

    private KeyPair keyPair;
    private GoogleIdTokenVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        verifier = new GoogleIdTokenVerifier(CLIENT_ID,
                GoogleIdTokenVerifier.withStringIssuer(
                        NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build()));
    }

    private String idToken(String issuer, String audience, Date expiration, KeyPair signer)
            throws Exception {
        return idToken(issuer, audience, expiration, signer, true);
    }

    private String idToken(String issuer, String audience, Date expiration, KeyPair signer,
                           boolean emailVerified) throws Exception {
        return Jwts.builder()
                .setSubject("google-sub-1")
                .setIssuer(issuer)
                .setAudience(audience)
                .claim("email", "user@example.com")
                .claim("name", "User Example")
                .claim("email_verified", emailVerified)
                .setExpiration(expiration)
                .signWith(signer.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
    }

    @Test
    void verifiesValidGoogleToken() throws Exception {
        String token = idToken("https://accounts.google.com", CLIENT_ID,
                new Date(System.currentTimeMillis() + 60_000), keyPair);

        Jwt jwt = verifier.verify(token);

        assertThat(jwt.getSubject()).isEqualTo("google-sub-1");
        assertThat(jwt.getClaimAsString("email")).isEqualTo("user@example.com");
    }

    @Test
    void acceptsShortIssuerForm() throws Exception {
        String token = idToken("accounts.google.com", CLIENT_ID,
                new Date(System.currentTimeMillis() + 60_000), keyPair);

        assertThat(verifier.verify(token)).isNotNull();
    }

    @Test
    void rejectsWrongIssuer() throws Exception {
        String token = idToken("https://evil.example.com", CLIENT_ID,
                new Date(System.currentTimeMillis() + 60_000), keyPair);

        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void rejectsWrongAudience() throws Exception {
        String token = idToken("https://accounts.google.com", "other-client",
                new Date(System.currentTimeMillis() + 60_000), keyPair);

        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("audience");
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        String token = idToken("https://accounts.google.com", CLIENT_ID,
                new Date(System.currentTimeMillis() - 60_000), keyPair);

        assertThatThrownBy(() -> verifier.verify(token)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsInvalidSignature() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair attacker = generator.generateKeyPair();

        String token = idToken("https://accounts.google.com", CLIENT_ID,
                new Date(System.currentTimeMillis() + 60_000), attacker);

        assertThatThrownBy(() -> verifier.verify(token)).isInstanceOf(JwtException.class);
    }

    /** Un email no verificado por Google se rechaza aunque firma/iss/aud sean validos. */
    @Test
    void rejectsUnverifiedEmail() throws Exception {
        String token = idToken("https://accounts.google.com", CLIENT_ID,
                new Date(System.currentTimeMillis() + 60_000), keyPair, false);

        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("not verified");
    }
}
