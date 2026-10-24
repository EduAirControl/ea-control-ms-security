package com.eduaircontrol.mssecurity.infrastructure.outbound.redis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

class RedisSocialCodeStoreTest {

    private static final UUID USER_ID = UUID.randomUUID();

    private StringRedisTemplate redis;
    private ValueOperations<String, String> ops;
    private RedisSocialCodeStore store;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        ops = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(ops);
        store = new RedisSocialCodeStore(redis);
    }

    @Test
    void storesCodeWithShortTtl() {
        store.store("code-abc", USER_ID);

        ArgumentCaptor<Duration> ttl = ArgumentCaptor.forClass(Duration.class);
        verify(ops).set(eq("social-code:code-abc"), eq(USER_ID.toString()), ttl.capture());
        assertThat(ttl.getValue()).isPositive();
        assertThat(ttl.getValue()).isLessThanOrEqualTo(RedisSocialCodeStore.TTL);
    }

    @Test
    void consumeReturnsUserAndDeletesTheCode() {
        when(ops.getAndDelete("social-code:code-abc")).thenReturn(USER_ID.toString());

        UUID userId = store.consume("code-abc");

        assertThat(userId).isEqualTo(USER_ID);
        verify(ops).getAndDelete("social-code:code-abc");
    }

    @Test
    void consumeReturnsNullForUnknownCode() {
        when(ops.getAndDelete("social-code:nope")).thenReturn(null);

        assertThat(store.consume("nope")).isNull();
    }

    @Test
    void consumeReturnsNullForMalformedValue() {
        when(ops.getAndDelete("social-code:bad")).thenReturn("not-a-uuid");

        assertThat(store.consume("bad")).isNull();
    }

    @Test
    void skipsBlankCodeAndUser() {
        store.store(" ", USER_ID);
        store.store("code-abc", null);
        store.store(null, USER_ID);

        verify(ops, never()).set(anyString(), anyString(), any(Duration.class));
        assertThat(store.consume(null)).isNull();
        assertThat(store.consume(" ")).isNull();
        verify(ops, never()).getAndDelete(anyString());
    }
}
