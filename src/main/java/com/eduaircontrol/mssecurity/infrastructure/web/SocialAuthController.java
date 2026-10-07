package com.eduaircontrol.mssecurity.infrastructure.web;

import com.eduaircontrol.mssecurity.application.AuthResult;
import com.eduaircontrol.mssecurity.application.AuthService;
import com.eduaircontrol.mssecurity.application.SocialAuthService;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.AuthResponse;
import com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto.UserSummary;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Login social (Google, Facebook). El frontend redirige al proveedor OAuth2,
 * el proveedor llama al callback, y aqui se crea/vincula el usuario y se
 * emite un JWT.
 */
@RestController
@RequestMapping("/api/v1/auth/oauth2")
@RequiredArgsConstructor
public class SocialAuthController {

    private final SocialAuthService socialAuthService;
    private final AuthService authService;

    /**
     * Callback del proveedor social. Recibe los datos del usuario ya
     * verificados por el proveedor y devuelve un JWT.
     */
    @PostMapping("/{provider}/callback")
    public ResponseEntity<AuthResponse> callback(
            @PathVariable String provider,
            @Valid @RequestBody SocialCallbackRequest request) {

        String normalizedProvider = provider.toLowerCase();
        if (!normalizedProvider.equals("google") && !normalizedProvider.equals("facebook")) {
            return ResponseEntity.badRequest().build();
        }

        SocialAuthService.SocialResult result = socialAuthService.findOrCreate(
                normalizedProvider,
                request.providerUserId(),
                request.email(),
                request.displayName(),
                request.avatarUrl());

        // Generar JWT via AuthService (reutiliza la logica de tokens)
        AuthResult tokens = authService.loginWithUser(result.user());
        return ResponseEntity.ok(toResponse(tokens));
    }

    /**
     * Asigna la institucion al usuario social despues del primer login.
     */
    @PostMapping("/onboarding")
    public ResponseEntity<Void> onboarding(@Valid @RequestBody OnboardingRequest request) {
        socialAuthService.assignInstitution(request.userId(), request.institutionId());
        return ResponseEntity.noContent().build();
    }

    private AuthResponse toResponse(AuthResult result) {
        return new AuthResponse(
                result.accessToken(),
                result.refreshToken(),
                result.expiresIn(),
                new UserSummary(result.userId(), result.email(), result.username(),
                        result.roles(), java.util.List.of(), result.institutionId(), result.campusId()));
    }

    public record SocialCallbackRequest(
            @NotBlank String providerUserId,
            String email,
            String displayName,
            String avatarUrl) {
    }

    public record OnboardingRequest(
            @NotBlank UUID userId,
            @NotBlank UUID institutionId) {
    }
}
