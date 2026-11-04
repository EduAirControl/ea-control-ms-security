package com.eduaircontrol.mssecurity.infrastructure.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * Cookies httpOnly de sesion del BFF web ({@code access_token}, {@code refresh_token}).
 * Las comparten el login por contrasena y el canje del login social.
 */
@Component
public class AuthCookies {

    private static final long REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60;

    @Value("${COOKIE_SECURE:false}")
    private boolean cookieSecure;

    public void set(HttpServletResponse response, String accessToken, String refreshToken,
            long accessExpiresIn) {
        response.addHeader(HttpHeaders.SET_COOKIE, build("access_token", accessToken, accessExpiresIn));
        response.addHeader(HttpHeaders.SET_COOKIE, build("refresh_token", refreshToken, REFRESH_TTL_SECONDS));
    }

    public void clear(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, build("access_token", "", 0));
        response.addHeader(HttpHeaders.SET_COOKIE, build("refresh_token", "", 0));
    }

    private String build(String name, String value, long maxAgeSeconds) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/")
                .maxAge(maxAgeSeconds)
                .build()
                .toString();
    }
}
