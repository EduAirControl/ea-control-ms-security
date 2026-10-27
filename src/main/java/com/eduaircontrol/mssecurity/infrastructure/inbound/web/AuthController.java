package com.eduaircontrol.mssecurity.infrastructure.inbound.web;

import com.eduaircontrol.mssecurity.application.AuthResult;
import com.eduaircontrol.mssecurity.application.AuthService;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.AuthResponse;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.LoginRequest;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.LogoutRequest;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.RegisterRequest;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.RefreshRequest;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.ServiceHealthResponse;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.UserSummary;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import jakarta.validation.Valid;
import java.sql.Connection;
import java.util.UUID;
import javax.sql.DataSource;
import com.eduaircontrol.mssecurity.domain.exception.UnauthorizedException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoints del contrato auth-service.yaml bajo /api/v1/auth:
 * register, login, refresh, logout y health.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final DataSource dataSource;
    private final StringRedisTemplate redis;

    @Value("${COOKIE_SECURE:false}")
    private boolean cookieSecure;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        AuthResult result = authService.register(
                request.email(), request.password(), request.username(), request.companyCode(),
                request.campusId(), userAgent(httpRequest));
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(result));
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        AuthResponse response = toResponse(authService.login(request.email(), request.password(), userAgent(httpRequest)));
        setAuthCookies(httpResponse, response.accessToken(), response.refreshToken(), response.expiresIn());
        return response;
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody(required = false) RefreshRequest request, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        String refreshToken = (request == null || request.refreshToken() == null || request.refreshToken().isBlank())
                ? readCookie(httpRequest, "refresh_token")
                : request.refreshToken();
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new UnauthorizedException("REFRESH_TOKEN_INVALID", "Refresh token invalid, expired, or already used");
        }
        AuthResponse response = toResponse(authService.refresh(refreshToken, userAgent(httpRequest)));
        setAuthCookies(httpResponse, response.accessToken(), response.refreshToken(), response.expiresIn());
        return response;
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody(required = false) LogoutRequest request,
            Authentication authentication, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        UUID userId = UUID.fromString(authentication.getName());
        String refreshToken = request == null ? null : request.refreshToken();
        if (refreshToken == null || refreshToken.isBlank()) {
            refreshToken = readCookie(httpRequest, "refresh_token");
        }
        boolean allDevices = request != null && Boolean.TRUE.equals(request.allDevices());
        String jti = (String) httpRequest.getAttribute("jwtJti");
        java.time.Instant expiresAt = (java.time.Instant) httpRequest.getAttribute("jwtExp");
        authService.logout(userId, refreshToken, allDevices, jti, expiresAt);
        clearAuthCookies(httpResponse);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/health")
    public ResponseEntity<ServiceHealthResponse> health() {
        String redisStatus = redisStatus();
        try (Connection connection = dataSource.getConnection()) {
            if (connection.isValid(2)) {
                return ResponseEntity.ok(ServiceHealthResponse.healthy(redisStatus));
            }
        } catch (Exception e) {
            // database down — handled below
        }
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(ServiceHealthResponse.databaseDown(redisStatus));
    }

    private String redisStatus() {
        try {
            redis.execute((RedisCallback<Void>) connection -> {
                connection.ping();
                return null;
            });
            return "connected";
        } catch (Exception e) {
            return "disconnected";
        }
    }

    private String userAgent(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }

    private void setAuthCookies(HttpServletResponse response, String accessToken, String refreshToken,
            long accessExpiresIn) {
        ResponseCookie access = ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/")
                .maxAge(accessExpiresIn)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, access.toString());

        ResponseCookie refresh = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/")
                .maxAge(7 * 24 * 60 * 60)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, refresh.toString());
    }

    private void clearAuthCookies(HttpServletResponse response) {
        ResponseCookie access = ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, access.toString());

        ResponseCookie refresh = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, refresh.toString());
    }

    private String readCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) {
            return null;
        }
        for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private AuthResponse toResponse(AuthResult result) {
        return new AuthResponse(
                result.accessToken(),
                result.refreshToken(),
                result.expiresIn(),
                new UserSummary(result.userId(), result.email(), result.username(),
                        result.roles(), java.util.List.of(), result.institutionId(), result.campusId()));
    }
}
