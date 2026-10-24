package com.eduaircontrol.mssecurity.infrastructure.outbound.redis;

import com.eduaircontrol.mssecurity.application.port.SocialCodeStore;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * Implementa los códigos sociales en Redis con clave {@code social-code:{code}}
 * y TTL corto. El consume es atómico (GETDEL): el código muere al canjearse.
 */
@Component
@RequiredArgsConstructor
public class RedisSocialCodeStore implements SocialCodeStore {

    static final String PREFIX = "social-code:";
    static final Duration TTL = Duration.ofSeconds(60);

    private final StringRedisTemplate redis;

    @Override
    public void store(String code, UUID userId) {
        if (code == null || code.isBlank() || userId == null) {
            return;
        }
        redis.opsForValue().set(PREFIX + code, userId.toString(), TTL);
    }

    @Override
    public UUID consume(String code) {
        if (code == null || code.isBlank()) {
            return null;
        }
        String value = redis.opsForValue().getAndDelete(PREFIX + code);
        if (value == null) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
