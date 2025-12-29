package com.khaounen.security.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.khaounen.config.RequestContext;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.core.RedisTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class RateLimitService {

    private final ObjectProvider<RedisTemplate<String, Long>> redisTemplateProvider;
    private final FingerprintStrategy fingerprintStrategy;

    private final Cache<String, Counter> localCounters = Caffeine.newBuilder()
            .expireAfter(new CounterExpiry())
            .build();
    private final Cache<String, Counter> localBlocks = Caffeine.newBuilder()
            .expireAfter(new CounterExpiry())
            .build();

    public RateLimitService(
            ObjectProvider<RedisTemplate<String, Long>> redisTemplateProvider,
            FingerprintStrategy fingerprintStrategy
    ) {
        this.redisTemplateProvider = redisTemplateProvider;
        this.fingerprintStrategy = fingerprintStrategy;
    }

    public RateLimitDecision check(RateLimitProperties.Rule rule, boolean authenticated, String identifier) {
        String fingerprint = fingerprintOrGenerate();
        String ruleKey = buildRuleKey(rule);
        int maxRequests = applyMultiplier(rule.getMaxRequests(), rule.getAuthenticatedMultiplier(), authenticated, rule.isApplyAuthenticatedMultiplier());
        int windowSeconds = Math.max(1, rule.getWindowSeconds());
        int blockSeconds = Math.max(1, rule.getBlockSeconds());

        if (redisTemplateProvider.getIfAvailable() != null) {
            return checkRedis(
                    ruleKey,
                    fingerprint,
                    identifier,
                    maxRequests,
                    windowSeconds,
                    blockSeconds
            );
        }

        return checkLocal(ruleKey, fingerprint, identifier, maxRequests, windowSeconds, blockSeconds);
    }

    private RateLimitDecision checkRedis(
            String ruleKey,
            String fingerprint,
            String identifier,
            int maxRequests,
            int windowSeconds,
            int blockSeconds
    ) {
        RedisTemplate<String, Long> redis = redisTemplateProvider.getIfAvailable();
        if (redis == null) {
            return checkLocal(ruleKey, fingerprint, identifier, maxRequests, windowSeconds, blockSeconds);
        }
        try {
            Long retryAfter = blockedRetryAfter(redis, ruleKey, fingerprint, identifier);
            if (retryAfter != null) {
                return RateLimitDecision.block(retryAfter);
            }
            boolean overLimit = incrementRedis(redis, ruleKey, fingerprint, maxRequests, windowSeconds);
            if (identifier != null) {
                String hashed = hash(identifier);
                overLimit = overLimit || incrementRedis(redis, ruleKey, hashed, maxRequests, windowSeconds);
            }
            if (overLimit) {
                redis.opsForValue().set(blockKey(ruleKey, fingerprint), 1L, Duration.ofSeconds(blockSeconds));
                if (identifier != null) {
                    redis.opsForValue().set(blockKey(ruleKey, hash(identifier)), 1L, Duration.ofSeconds(blockSeconds));
                }
                return RateLimitDecision.block(blockSeconds);
            }
            return RateLimitDecision.allow();
        } catch (Exception ex) {
            return checkLocal(ruleKey, fingerprint, identifier, maxRequests, windowSeconds, blockSeconds);
        }
    }

    private RateLimitDecision checkLocal(
            String ruleKey,
            String fingerprint,
            String identifier,
            int maxRequests,
            int windowSeconds,
            int blockSeconds
    ) {
        long now = System.currentTimeMillis();
        String blockKey = blockKey(ruleKey, fingerprint);
        Counter block = localBlocks.getIfPresent(blockKey);
        if (block != null) {
            if (block.expiresAt > now) {
                long retryAfterSeconds = (block.expiresAt - now) / 1000;
                return RateLimitDecision.block(retryAfterSeconds);
            }
            localBlocks.invalidate(blockKey);
        }

        boolean overLimit = incrementLocal(ruleKey, fingerprint, maxRequests, windowSeconds, now);
        if (identifier != null) {
            overLimit = overLimit || incrementLocal(ruleKey, hash(identifier), maxRequests, windowSeconds, now);
        }

        if (overLimit) {
            localBlocks.put(blockKey, new Counter(1, now + (blockSeconds * 1000L)));
            if (identifier != null) {
                localBlocks.put(blockKey(ruleKey, hash(identifier)), new Counter(1, now + (blockSeconds * 1000L)));
            }
            return RateLimitDecision.block(blockSeconds);
        }

        return RateLimitDecision.allow();
    }

    private boolean incrementLocal(String ruleKey, String keyPart, int maxRequests, int windowSeconds, long now) {
        String countKey = countKey(ruleKey, keyPart);
        Counter counter = localCounters.asMap().compute(countKey, (key, existing) -> {
            if (existing == null || existing.expiresAt <= now) {
                return new Counter(1, now + (windowSeconds * 1000L));
            }
            existing.count += 1;
            return existing;
        });
        return counter.count > maxRequests;
    }

    private static int applyMultiplier(int maxRequests, int multiplier, boolean authenticated, boolean applyMultiplier) {
        int safeMax = Math.max(1, maxRequests);
        int safeMultiplier = Math.max(1, multiplier);
        if (!authenticated || !applyMultiplier) {
            return safeMax;
        }
        long scaled = (long) safeMax * safeMultiplier;
        return (int) Math.min(Integer.MAX_VALUE, scaled);
    }

    private static String countKey(String ruleKey, String keyPart) {
        return "rate:count:" + ruleKey + ":" + keyPart;
    }

    private static String blockKey(String ruleKey, String keyPart) {
        return "rate:block:" + ruleKey + ":" + keyPart;
    }

    private static String buildRuleKey(RateLimitProperties.Rule rule) {
        if (rule.getKey() != null && !rule.getKey().isBlank()) {
            return appendSuffix(rule.getKey(), rule.getKeySuffix());
        }
        return appendSuffix(rule.getPath().replace('/', '_'), rule.getKeySuffix());
    }

    private static String appendSuffix(String key, String suffix) {
        if (suffix == null || suffix.isBlank()) {
            return key;
        }
        return key + ":" + suffix;
    }

    private static boolean incrementRedis(
            RedisTemplate<String, Long> redis,
            String ruleKey,
            String keyPart,
            int maxRequests,
            int windowSeconds
    ) {
        String countKey = countKey(ruleKey, keyPart);
        Long count = redis.opsForValue().increment(countKey);
        if (count != null && count == 1L) {
            redis.expire(countKey, Duration.ofSeconds(windowSeconds));
        }
        return count != null && count > maxRequests;
    }

    private static Long blockedRetryAfter(
            RedisTemplate<String, Long> redis,
            String ruleKey,
            String fingerprint,
            String identifier
    ) {
        Long ttl = ttlSeconds(redis, blockKey(ruleKey, fingerprint));
        if (ttl != null) {
            return ttl;
        }
        if (identifier != null) {
            Long ttlIdentifier = ttlSeconds(redis, blockKey(ruleKey, hash(identifier)));
            if (ttlIdentifier != null) {
                return ttlIdentifier;
            }
        }
        return null;
    }

    private static Long ttlSeconds(RedisTemplate<String, Long> redis, String key) {
        Boolean blocked = redis.hasKey(key);
        if (!Boolean.TRUE.equals(blocked)) {
            return null;
        }
        Long ttl = redis.getExpire(key);
        return ttl != null && ttl > 0 ? ttl : 0;
    }

    private static String hash(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "hash_error";
        }
    }

    private String fingerprintOrGenerate() {
        String fingerprint = RequestContext.getFingerprint();
        if (fingerprint != null) {
            return fingerprint;
        }
        return fingerprintStrategy.generate(null);
    }

    private static class Counter {
        private long count;
        private long expiresAt;

        private Counter(long count, long expiresAt) {
            this.count = count;
            this.expiresAt = expiresAt;
        }
    }

    private static class CounterExpiry implements Expiry<String, Counter> {
        @Override
        public long expireAfterCreate(String key, Counter value, long currentTime) {
            return remainingNanos(value, currentTime);
        }

        @Override
        public long expireAfterUpdate(String key, Counter value, long currentTime, long currentDuration) {
            return remainingNanos(value, currentTime);
        }

        @Override
        public long expireAfterRead(String key, Counter value, long currentTime, long currentDuration) {
            return currentDuration;
        }

        private long remainingNanos(Counter value, long currentTime) {
            long nowMillis = TimeUnit.NANOSECONDS.toMillis(currentTime);
            long remainingMillis = value.expiresAt - nowMillis;
            if (remainingMillis <= 0) {
                return 0;
            }
            return TimeUnit.MILLISECONDS.toNanos(remainingMillis);
        }
    }
}
