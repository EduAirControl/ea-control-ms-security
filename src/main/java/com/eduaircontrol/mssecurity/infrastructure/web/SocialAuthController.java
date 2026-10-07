package com.eduaircontrol.mssecurity.infrastructure.web;

import com.eduaircontrol.mssecurity.application.AuthResult;
import com.eduaircontrol.mssecurity.application.AuthService;
import com.eduaircontrol.mssecurity.application.SocialAuthService;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.AuthResponse;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.UserSummary;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Login social (Google, Facebook). El frontend envia el credential/token del
 * proveedor y aqui se verifica, se crea/vincula el usuario y se emite un JWT.
 */
@RestController
@RequestMapping("/api/v1/auth/oauth2")
@RequiredArgsConstructor
public class SocialAuthController {

    private final SocialAuthService socialAuthService;
    private final AuthService authService;
    private final ObjectMapper objectMapper;

    @Value("${google.client-id:}")
    private String googleClientId;

    /**
     * Login con Google Identity Services (GIS). Recibe el credential JWT de
     * Google y lo verifica contra el tokeninfo de Google.
     */
    @PostMapping("/google/callback")
    public ResponseEntity<AuthResponse> googleCallback(@Valid @RequestBody GoogleCallbackRequest request) {
        try {
            JsonNode payload = verifyGoogleToken(request.credential());
            if (payload == null) {
                return ResponseEntity.status(401).build();
            }

            String email = payload.path("email").asText("");
            String name = payload.path("name").asText("");
            String picture = payload.path("picture").asText("");
            String sub = payload.path("sub").asText("");

            SocialAuthService.SocialResult result = socialAuthService.findOrCreate(
                    "google", sub, email, name, picture);

            AuthResult tokens = authService.loginWithUser(result.user());
            return ResponseEntity.ok(toResponse(tokens));
        } catch (Exception e) {
            return ResponseEntity.status(401).build();
        }
    }

    /**
     * Login con Facebook. Recibe el access token de Facebook y lo verifica.
     */
    @PostMapping("/facebook/callback")
    public ResponseEntity<AuthResponse> facebookCallback(@Valid @RequestBody FacebookCallbackRequest request) {
        try {
            JsonNode payload = verifyFacebookToken(request.accessToken());
            if (payload == null) {
                return ResponseEntity.status(401).build();
            }

            String email = payload.path("email").asText("");
            String name = payload.path("name").asText("");
            String picture = payload.path("picture").path("data").path("url").asText("");
            String sub = payload.path("id").asText("");

            SocialAuthService.SocialResult result = socialAuthService.findOrCreate(
                    "facebook", sub, email, name, picture);

            AuthResult tokens = authService.loginWithUser(result.user());
            return ResponseEntity.ok(toResponse(tokens));
        } catch (Exception e) {
            return ResponseEntity.status(401).build();
        }
    }

    /**
     * Asigna la institucion al usuario social despues del primer login.
     */
    @PostMapping("/onboarding")
    public ResponseEntity<Void> onboarding(@Valid @RequestBody OnboardingRequest request) {
        socialAuthService.assignInstitution(request.userId(), request.institutionId());
        return ResponseEntity.noContent().build();
    }

    /**
     * Verifica el ID token de Google contra el endpoint tokeninfo.
     */
    private JsonNode verifyGoogleToken(String credential) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("https://oauth2.googleapis.com/tokeninfo?id_token=" + credential))
                .GET()
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            return null;
        }
        JsonNode node = objectMapper.readTree(resp.body());
        // Verificar que el audience coincide con nuestro client ID
        if (googleClientId != null && !googleClientId.isEmpty()) {
            String aud = node.path("aud").asText("");
            if (!aud.equals(googleClientId)) {
                return null;
            }
        }
        return node;
    }

    /**
     * Verifica el access token de Facebook contra el endpoint de debug.
     */
    private JsonNode verifyFacebookToken(String accessToken) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("https://graph.facebook.com/me?fields=id,name,email,picture&access_token=" + accessToken))
                .GET()
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            return null;
        }
        return objectMapper.readTree(resp.body());
    }

    private AuthResponse toResponse(AuthResult result) {
        return new AuthResponse(
                result.accessToken(),
                result.refreshToken(),
                result.expiresIn(),
                new UserSummary(result.userId(), result.email(), result.username(),
                        result.roles(), java.util.List.of(), result.institutionId(), result.campusId()));
    }

    public record GoogleCallbackRequest(@NotBlank String credential) {
    }

    public record FacebookCallbackRequest(@NotBlank String accessToken) {
    }

    public record OnboardingRequest(@NotBlank UUID userId, @NotBlank UUID institutionId) {
    }
}
