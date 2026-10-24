package com.eduaircontrol.mssecurity.infrastructure.outbound.redis;

import com.eduaircontrol.mssecurity.application.port.SocialStateStore;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * {@code state} OAuth2 en Redis con clave {@code oauth2-state:{state}} y TTL
 * corto. El consume es atomico (GETDEL): el state muere al usarse (single-use).
 */
@Component
@RequiredArgsConstructor
public class RedisSocialStateStore implements SocialStateStore {

    static final String PREFIX = "oauth2-state:";
    static final Duration TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate redis;

    @Override
    public void store(String state, String provider) {
        if (state == null || state.isBlank()) {
            return;
        }
        redis.opsForValue().set(PREFIX + state, provider == null ? "" : provider, TTL);
    }

    @Override
    public String consume(String state) {
        if (state == null || state.isBlank()) {
            return null;
        }
        return redis.opsForValue().getAndDelete(PREFIX + state);
    }
}
