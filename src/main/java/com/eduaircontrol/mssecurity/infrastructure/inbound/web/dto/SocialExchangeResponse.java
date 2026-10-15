package com.eduaircontrol.mssecurity.infrastructure.inbound.web.dto;

import java.util.UUID;

/**
 * Respuesta del canje del codigo social por tokens (mismo formato que
 * {@link AuthResponse} mas la señal de onboarding pendiente).
 */
public record SocialExchangeResponse(String accessToken, String refreshToken, long expiresIn,
        UserSummary user, boolean needsOnboarding) {
}
