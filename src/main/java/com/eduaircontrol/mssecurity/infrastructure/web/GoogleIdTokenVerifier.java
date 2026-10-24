package com.eduaircontrol.mssecurity.infrastructure.web;

import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

/**
 * Verifica el ID token de Google con la clave pública real de Google (JWKS),
 * no con el endpoint deprecado {@code tokeninfo}. Valida firma, emisor,
 * audiencia y expiración.
 */
@Component
public class GoogleIdTokenVerifier {

    static final String GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";
    static final String ISSUER = "https://accounts.google.com";
    static final String ISSUER_SHORT = "accounts.google.com";

    private final String clientId;
    private final JwtDecoder decoder;

    @Autowired
    public GoogleIdTokenVerifier(@Value("${google.client-id:}") String clientId) {
        this(clientId, withStringIssuer(NimbusJwtDecoder.withJwkSetUri(GOOGLE_JWKS_URI).build()));
    }

    GoogleIdTokenVerifier(String clientId, JwtDecoder decoder) {
        this.clientId = clientId;
        this.decoder = decoder;
    }

    /**
     * El converter por defecto mapea {@code iss} a URL y falla con la forma
     * corta ({@code accounts.google.com}); aquí se deja como texto plano.
     */
    static JwtDecoder withStringIssuer(JwtDecoder decoder) {
        if (decoder instanceof NimbusJwtDecoder nimbus) {
            Map<String, Converter<Object, ?>> custom = new HashMap<>();
            custom.put("iss", value -> value);
            nimbus.setClaimSetConverter(MappedJwtClaimSetConverter.withDefaults(custom));
        }
        return decoder;
    }

    /** Lanza {@link JwtException} si el token no es válido. */
    public Jwt verify(String idToken) {
        Jwt jwt = decoder.decode(idToken);
        String issuer = jwt.getClaimAsString("iss");
        if (!ISSUER.equals(issuer) && !ISSUER_SHORT.equals(issuer)) {
            throw new JwtException("Unexpected issuer: " + issuer);
        }
        if (clientId != null && !clientId.isBlank()
                && (jwt.getAudience() == null || !jwt.getAudience().contains(clientId))) {
            throw new JwtException("Token audience does not match google.client-id");
        }
        // Un email NO verificado por Google no puede usarse para vincular ni para
        // autoaprovisionar: es como enlazar una cuenta ajena con un email sin
        // confirmar. Se rechaza el token entero.
        if (!isTrue(jwt.getClaim("email_verified"))) {
            throw new JwtException("Google account email is not verified");
        }
        return jwt;
    }

    /** El claim puede venir como booleano o como cadena "true". */
    private static boolean isTrue(Object value) {
        return Boolean.TRUE.equals(value) || "true".equalsIgnoreCase(String.valueOf(value));
    }
}
