package com.eduaircontrol.mssecurity.infrastructure.web;

import com.eduaircontrol.mssecurity.application.AuthResult;
import com.eduaircontrol.mssecurity.application.AuthService;
import com.eduaircontrol.mssecurity.application.SocialAuthService;
import com.eduaircontrol.mssecurity.application.port.SocialCodeStore;
import com.eduaircontrol.mssecurity.domain.exception.UnauthorizedException;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.SocialExchangeResponse;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.UserSummary;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Login social (Google, Facebook) via OAuth2 Authorization Code Flow.
 * El frontend redirige aqui, el backend redirige al proveedor, y el callback
 * deja un codigo social de un solo uso que el frontend canjea por tokens en
 * {@code POST /social/exchange}. Los tokens nunca viajan en la URL.
 */
@RestController
@RequestMapping("/api/v1/auth/oauth2")
@RequiredArgsConstructor
public class SocialAuthController {

    private final SocialAuthService socialAuthService;
    private final AuthService authService;
    private final SocialCodeStore socialCodeStore;
    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${google.client-id:}")
    private String googleClientId;

    @Value("${google.client-secret:}")
    private String googleClientSecret;

    @Value("${facebook.app-id:}")
    private String facebookAppId;

    @Value("${facebook.app-secret:}")
    private String facebookAppSecret;

    @Value("${app.frontend-url:http://localhost:5173}")
    private String frontendUrl;

    /** Base URL publica del backend para los callbacks (debe coincidir con el proveedor). */
    @Value("${app.social.callback-base-url:}")
    private String socialCallbackBaseUrl;

    @Value("${app.oauth2.issuer:http://localhost:8081}")
    private String issuer;

    // ===================== GOOGLE =====================

    @GetMapping("/google")
    public void googleAuth(HttpServletResponse response) throws IOException {
        String redirectUri = getRedirectUri("google");
        String params = String.join("&",
                "client_id=" + googleClientId,
                "redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8),
                "response_type=code",
                "scope=openid%20email%20profile",
                "access_type=online",
                "prompt=select_account");
        response.sendRedirect("https://accounts.google.com/o/oauth2/v2/auth?" + params);
    }

    @GetMapping("/google/callback")
    public void googleCallback(@RequestParam("code") String code,
                               HttpServletResponse response) throws Exception {
        // 1. Intercambiar code por tokens
        String redirectUri = getRedirectUri("google");
        String body = "code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                + "&client_id=" + URLEncoder.encode(googleClientId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(googleClientSecret, StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&grant_type=authorization_code";

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest tokenReq = HttpRequest.newBuilder()
                .uri(URI.create("https://oauth2.googleapis.com/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> tokenResp = client.send(tokenReq, HttpResponse.BodyHandlers.ofString());

        JsonNode tokenData = objectMapper.readTree(tokenResp.body());
        String idToken = tokenData.path("id_token").asText("");
        if (idToken.isEmpty()) {
            response.sendRedirect(frontendUrl + "/login?error=auth_failed");
            return;
        }

        // 2. Verificar el ID token (firma JWKS de Google, iss, aud, exp)
        Jwt payload;
        try {
            payload = googleIdTokenVerifier.verify(idToken);
        } catch (RuntimeException e) {
            response.sendRedirect(frontendUrl + "/login?error=auth_failed");
            return;
        }

        // 3. Crear/vincular usuario y dejar codigo social de un solo uso
        String email = payload.getClaimAsString("email");
        String name = payload.getClaimAsString("name");
        String picture = payload.getClaimAsString("picture");
        String sub = payload.getSubject();

        SocialAuthService.SocialResult result = socialAuthService.findOrCreate(
                "google", sub, email, name, picture);
        redirectToFrontendWithCode(response, result.user().getId());
    }

    // ===================== FACEBOOK =====================

    @GetMapping("/facebook")
    public void facebookAuth(HttpServletResponse response) throws IOException {
        String redirectUri = getRedirectUri("facebook");
        String params = String.join("&",
                "client_id=" + facebookAppId,
                "redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8),
                "response_type=code",
                "scope=public_profile%2Cemail");
        response.sendRedirect("https://www.facebook.com/v18.0/dialog/oauth?" + params);
    }

    @GetMapping("/facebook/callback")
    public void facebookCallback(@RequestParam("code") String code,
                                 HttpServletResponse response) throws Exception {
        String redirectUri = getRedirectUri("facebook");
        String body = "code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                + "&client_id=" + URLEncoder.encode(facebookAppId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(facebookAppSecret, StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest tokenReq = HttpRequest.newBuilder()
                .uri(URI.create("https://graph.facebook.com/v18.0/oauth/access_token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> tokenResp = client.send(tokenReq, HttpResponse.BodyHandlers.ofString());

        JsonNode tokenData = objectMapper.readTree(tokenResp.body());
        String accessToken = tokenData.path("access_token").asText("");
        if (accessToken.isEmpty()) {
            response.sendRedirect(frontendUrl + "/login?error=auth_failed");
            return;
        }

        // Obtener datos del usuario (appsecret_proof: la llamada solo vale para nuestra app)
        String meUrl = "https://graph.facebook.com/me?fields=id,name,email,picture"
                + "&access_token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
        String appSecretProof = appSecretProof(accessToken);
        if (appSecretProof != null) {
            meUrl += "&appsecret_proof=" + appSecretProof;
        }
        HttpRequest userReq = HttpRequest.newBuilder().uri(URI.create(meUrl)).GET().build();
        HttpResponse<String> userResp = client.send(userReq, HttpResponse.BodyHandlers.ofString());
        JsonNode payload = objectMapper.readTree(userResp.body());

        String email = payload.path("email").asText("");
        String name = payload.path("name").asText("");
        String picture = payload.path("picture").path("data").path("url").asText("");
        String sub = payload.path("id").asText("");

        SocialAuthService.SocialResult result = socialAuthService.findOrCreate(
                "facebook", sub, email, name, picture);
        redirectToFrontendWithCode(response, result.user().getId());
    }

    // ===================== EXCHANGE =====================

    /**
     * Canjea el codigo social de un solo uso por los tokens de sesion.
     * El codigo se quema aqui: solo puede canjearse una vez.
     */
    @PostMapping("/social/exchange")
    public SocialExchangeResponse exchange(@Valid @RequestBody SocialExchangeRequest request) {
        UUID userId = socialCodeStore.consume(request.code());
        if (userId == null) {
            throw new UnauthorizedException("Invalid or expired social code");
        }
        AuthResult result = authService.loginWithUser(userId);
        return new SocialExchangeResponse(
                result.accessToken(),
                result.refreshToken(),
                result.expiresIn(),
                new UserSummary(result.userId(), result.email(), result.username(),
                        result.roles(), java.util.List.of(), result.institutionId(), result.campusId()),
                result.institutionId() == null);
    }

    // ===================== ONBOARDING =====================

    /**
     * Asigna la institucion al usuario social recien creado. Requiere token:
     * el usuario sale del propio token, no del body.
     */
    @PostMapping("/onboarding")
    public ResponseEntity<Void> onboarding(Authentication authentication,
            @Valid @RequestBody OnboardingRequest request) {
        if (authentication == null || authentication.getName() == null) {
            throw new UnauthorizedException("Authentication token required");
        }
        UUID userId = UUID.fromString(authentication.getName());
        socialAuthService.assignInstitution(userId, request.companyCode());
        return ResponseEntity.noContent().build();
    }

    // ===================== HELPERS =====================

    private void redirectToFrontendWithCode(HttpServletResponse response, UUID userId)
            throws IOException {
        String code = UUID.randomUUID().toString();
        socialCodeStore.store(code, userId);
        response.sendRedirect(frontendUrl + "/login?social_code=" + code);
    }

    private String getRedirectUri(String provider) {
        // El redirect URI debe coincidir con el registrado en cada proveedor.
        String base = (socialCallbackBaseUrl == null || socialCallbackBaseUrl.isBlank())
                ? issuer
                : socialCallbackBaseUrl;
        return base + "/api/v1/auth/oauth2/" + provider + "/callback";
    }

    /** HMAC-SHA256 del access token con el app secret de Facebook. */
    private String appSecretProof(String accessToken) {
        if (facebookAppSecret == null || facebookAppSecret.isBlank()) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(facebookAppSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(accessToken.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            return null;
        }
    }

    public record SocialExchangeRequest(@NotBlank String code) {
    }

    public record OnboardingRequest(
            @NotBlank @Pattern(regexp = "(?i)^[A-Z]{3}-\\d{4}$",
                    message = "companyCode must match the format ABC-0000") String companyCode) {
    }
}
