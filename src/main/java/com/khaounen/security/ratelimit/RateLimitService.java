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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class RateLimitService {

    private final ObjectProvider<RedisTemplate<String, Long>> redisTemplateProvider;
    private final FingerprintStrategy fingerprintStrategy;
    private final RateLimitAlertListener alertListener;
    private final RiskEvaluator riskEvaluator;

    private final Cache<String, Counter> localCounters = Caffeine.newBuilder()
            .expireAfter(new CounterExpiry())
            .build();
    private final Cache<String, Counter> localBlocks = Caffeine.newBuilder()
            .expireAfter(new CounterExpiry())
            .build();
    private final Cache<String, Counter> localIncidents = Caffeine.newBuilder()
            .expireAfter(new CounterExpiry())
            .build();
    private final Cache<String, Counter> localAlerts = Caffeine.newBuilder()
            .expireAfter(new CounterExpiry())
            .build();

    public RateLimitService(
            ObjectProvider<RedisTemplate<String, Long>> redisTemplateProvider,
            FingerprintStrategy fingerprintStrategy,
            RateLimitAlertListener alertListener,
            RiskEvaluator riskEvaluator
    ) {
        this.redisTemplateProvider = redisTemplateProvider;
        this.fingerprintStrategy = fingerprintStrategy;
        this.alertListener = alertListener;
        this.riskEvaluator = riskEvaluator;
    }

    public RateLimitDecision check(RateLimitProperties.Rule rule, RateLimitContext ctx) {
        RateLimitContext safeCtx = ctx == null
                ? new RateLimitContext(false, false, false, null, null, null, List.of())
                : ctx;
        String ruleKey = buildRuleKey(rule);
        boolean requireVerified = requiresVerified(rule);
        boolean multiplierEligible = requireVerified ? safeCtx.verified() : safeCtx.authenticated();
        int maxRequests = applyMultiplier(
                rule.getMaxRequests(),
                rule.getAuthenticatedMultiplier(),
                multiplierEligible,
                rule.isApplyAuthenticatedMultiplier()
        );
        if (requiresMobileAttestation(rule)) {
            maxRequests = applyMultiplier(
                    maxRequests,
                    rule.getMobileMultiplier(),
                    safeCtx.mobileAttested(),
                    true
            );
        }
        int windowSeconds = Math.max(1, rule.getWindowSeconds());
        int blockSeconds = Math.max(1, rule.getBlockSeconds());
        List<String> keyParts = buildKeyParts(rule, safeCtx);
        RateLimitProperties.OnLimitAction action = rule.getOnLimitAction();
        int riskWindowSeconds = Math.max(1, rule.getRiskWindowSeconds());

        if (redisTemplateProvider.getIfAvailable() != null) {
            RateLimitDecision decision = checkRedis(
                    ruleKey,
                    keyParts,
                    action,
                    maxRequests,
                    windowSeconds,
                    blockSeconds,
                    riskWindowSeconds,
                    safeCtx,
                    rule
            );
            notifyIfAlert(rule, safeCtx, decision);
            return decision;
        }

        RateLimitDecision decision = checkLocal(
                ruleKey,
                keyParts,
                action,
                maxRequests,
                windowSeconds,
                blockSeconds,
                riskWindowSeconds,
                safeCtx,
                rule
        );
        notifyIfAlert(rule, safeCtx, decision);
        return decision;
    }

    private RateLimitDecision checkRedis(
            String ruleKey,
            List<String> keyParts,
            RateLimitProperties.OnLimitAction action,
            int maxRequests,
            int windowSeconds,
            int blockSeconds,
            int riskWindowSeconds,
            RateLimitContext ctx,
            RateLimitProperties.Rule rule
    ) {
        RedisTemplate<String, Long> redis = redisTemplateProvider.getIfAvailable();
        if (redis == null) {
            return checkLocal(
                    ruleKey,
                    keyParts,
                    action,
                    maxRequests,
                    windowSeconds,
                    blockSeconds,
                    riskWindowSeconds,
                    ctx,
                    rule
            );
        }
        try {
            if (action == RateLimitProperties.OnLimitAction.BLOCK || action == RateLimitProperties.OnLimitAction.BLOCK_AND_ALERT) {
                Long retryAfter = blockedRetryAfter(redis, ruleKey, keyParts);
                if (retryAfter != null) {
                    long incidentCount = shouldTrackIncidents(action) ? getIncidentCountRedis(redis, ruleKey, keyParts) : 0;
                    RateLimitDecision decision = RateLimitDecision.block(retryAfter);
                    if (action == RateLimitProperties.OnLimitAction.BLOCK_AND_ALERT
                            && shouldAlertOnBlock(redis, rule, ruleKey, keyParts, retryAfter)) {
                        decision = decision.withAlert(true);
                    }
                    return applyRisk(rule, ctx, decision, incidentCount);
                }
            }
            boolean overLimit = false;
            for (String keyPart : keyParts) {
                overLimit = incrementRedis(redis, ruleKey, keyPart, maxRequests, windowSeconds) || overLimit;
            }
            if (overLimit) {
                long incidentCount = shouldTrackIncidents(action)
                        ? recordIncidentsRedis(redis, ruleKey, keyParts, riskWindowSeconds)
                        : 0;
                if (action == RateLimitProperties.OnLimitAction.BLOCK || action == RateLimitProperties.OnLimitAction.BLOCK_AND_ALERT) {
                    boolean alert = action == RateLimitProperties.OnLimitAction.BLOCK_AND_ALERT
                            && shouldAlertOnNewBlock(redis, rule, ruleKey, keyParts, blockSeconds);
                    RateLimitDecision decision = RateLimitDecision.block(blockSeconds);
                    if (alert) {
                        decision = decision.withAlert(true);
                    }
                    RiskLevel riskLevel = evaluateRiskLevel(rule, ctx, decision, incidentCount);
                    int adjustedBlockSeconds = applyRiskBlockMultiplier(blockSeconds, riskLevel, rule);
                    if (adjustedBlockSeconds != blockSeconds) {
                        decision = RateLimitDecision.block(adjustedBlockSeconds);
                        if (alert) {
                            decision = decision.withAlert(true);
                        }
                    }
                    for (String keyPart : keyParts) {
                        redis.opsForValue().set(
                                blockKey(ruleKey, keyPart),
                                1L,
                                Duration.ofSeconds(adjustedBlockSeconds)
                        );
                    }
                    return decision.withRisk(riskLevel);
                }
                if (action == RateLimitProperties.OnLimitAction.CHALLENGE) {
                    return applyRisk(rule, ctx, RateLimitDecision.challenge(), incidentCount);
                }
                if (action == RateLimitProperties.OnLimitAction.ALERT || action == RateLimitProperties.OnLimitAction.ALERT_ONLY) {
                    return applyRisk(rule, ctx, RateLimitDecision.alertDecision(), incidentCount);
                }
            }
            long incidentCount = shouldTrackIncidents(action) ? getIncidentCountRedis(redis, ruleKey, keyParts) : 0;
            return applyRisk(rule, ctx, RateLimitDecision.allow(), incidentCount);
        } catch (Exception ex) {
            return checkLocal(
                    ruleKey,
                    keyParts,
                    action,
                    maxRequests,
                    windowSeconds,
                    blockSeconds,
                    riskWindowSeconds,
                    ctx,
                    rule
            );
        }
    }

    private RateLimitDecision checkLocal(
            String ruleKey,
            List<String> keyParts,
            RateLimitProperties.OnLimitAction action,
            int maxRequests,
            int windowSeconds,
            int blockSeconds,
            int riskWindowSeconds,
            RateLimitContext ctx,
            RateLimitProperties.Rule rule
    ) {
        long now = System.currentTimeMillis();
        if (action == RateLimitProperties.OnLimitAction.BLOCK || action == RateLimitProperties.OnLimitAction.BLOCK_AND_ALERT) {
            for (String keyPart : keyParts) {
                String blockKey = blockKey(ruleKey, keyPart);
                Counter block = localBlocks.getIfPresent(blockKey);
                if (block != null) {
                    if (block.expiresAt > now) {
                        long retryAfterSeconds = (block.expiresAt - now) / 1000;
                        long incidentCount = shouldTrackIncidents(action) ? getIncidentCountLocal(ruleKey, keyParts, now) : 0;
                        RateLimitDecision decision = RateLimitDecision.block(retryAfterSeconds);
                        if (action == RateLimitProperties.OnLimitAction.BLOCK_AND_ALERT
                                && shouldAlertOnBlockLocal(rule, ruleKey, keyParts, now, retryAfterSeconds)) {
                            decision = decision.withAlert(true);
                        }
                        return applyRisk(rule, ctx, decision, incidentCount);
                    }
                    localBlocks.invalidate(blockKey);
                }
            }
        }

        boolean overLimit = false;
        for (String keyPart : keyParts) {
            overLimit = incrementLocal(ruleKey, keyPart, maxRequests, windowSeconds, now) || overLimit;
        }

        if (overLimit) {
            long incidentCount = shouldTrackIncidents(action)
                    ? recordIncidentsLocal(ruleKey, keyParts, riskWindowSeconds, now)
                    : 0;
            if (action == RateLimitProperties.OnLimitAction.BLOCK || action == RateLimitProperties.OnLimitAction.BLOCK_AND_ALERT) {
                boolean alert = action == RateLimitProperties.OnLimitAction.BLOCK_AND_ALERT
                        && shouldAlertOnNewBlockLocal(rule, ruleKey, keyParts, now, blockSeconds);
                RateLimitDecision decision = RateLimitDecision.block(blockSeconds);
                if (alert) {
                    decision = decision.withAlert(true);
                }
                RiskLevel riskLevel = evaluateRiskLevel(rule, ctx, decision, incidentCount);
                int adjustedBlockSeconds = applyRiskBlockMultiplier(blockSeconds, riskLevel, rule);
                if (adjustedBlockSeconds != blockSeconds) {
                    decision = RateLimitDecision.block(adjustedBlockSeconds);
                    if (alert) {
                        decision = decision.withAlert(true);
                    }
                }
                for (String keyPart : keyParts) {
                    localBlocks.put(
                            blockKey(ruleKey, keyPart),
                            new Counter(1, now + (adjustedBlockSeconds * 1000L))
                    );
                }
                return decision.withRisk(riskLevel);
            }
            if (action == RateLimitProperties.OnLimitAction.CHALLENGE) {
                return applyRisk(rule, ctx, RateLimitDecision.challenge(), incidentCount);
            }
            if (action == RateLimitProperties.OnLimitAction.ALERT || action == RateLimitProperties.OnLimitAction.ALERT_ONLY) {
                return applyRisk(rule, ctx, RateLimitDecision.alertDecision(), incidentCount);
            }
        }

        long incidentCount = shouldTrackIncidents(action) ? getIncidentCountLocal(ruleKey, keyParts, now) : 0;
        return applyRisk(rule, ctx, RateLimitDecision.allow(), incidentCount);
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

    private static boolean requiresVerified(RateLimitProperties.Rule rule) {
        return rule.getKeyTypes() != null && rule.getKeyTypes().contains(RateLimitProperties.KeyType.VERIFIED_USER);
    }

    private static boolean requiresMobileAttestation(RateLimitProperties.Rule rule) {
        return rule.getKeyTypes() != null && rule.getKeyTypes().contains(RateLimitProperties.KeyType.MOBILE_ATTESTED);
    }

    private static String countKey(String ruleKey, String keyPart) {
        return "rate:count:" + ruleKey + ":" + keyPart;
    }

    private static String blockKey(String ruleKey, String keyPart) {
        return "rate:block:" + ruleKey + ":" + keyPart;
    }

    private static String alertKey(String ruleKey, String keyPart) {
        return "rate:alert:" + ruleKey + ":" + keyPart;
    }

    private static String incidentKey(String ruleKey, String keyPart) {
        return "rate:incident:" + ruleKey + ":" + keyPart;
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

    private static long incrementRedisCount(
            RedisTemplate<String, Long> redis,
            String ruleKey,
            String keyPart,
            int windowSeconds
    ) {
        String countKey = incidentKey(ruleKey, keyPart);
        Long count = redis.opsForValue().increment(countKey);
        if (count != null && count == 1L) {
            redis.expire(countKey, Duration.ofSeconds(windowSeconds));
        }
        return count == null ? 0 : count;
    }

    private static long readRedisCount(
            RedisTemplate<String, Long> redis,
            String ruleKey,
            String keyPart
    ) {
        String countKey = incidentKey(ruleKey, keyPart);
        Long count = redis.opsForValue().get(countKey);
        return count == null ? 0 : count;
    }

    private static Long blockedRetryAfter(
            RedisTemplate<String, Long> redis,
            String ruleKey,
            List<String> keyParts
    ) {
        for (String keyPart : keyParts) {
            Long ttl = ttlSeconds(redis, blockKey(ruleKey, keyPart));
            if (ttl != null) {
                return ttl;
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

    private List<String> buildKeyParts(RateLimitProperties.Rule rule, RateLimitContext ctx) {
        List<String> keyParts = new ArrayList<>();
        boolean hasExplicitTypes = rule.getKeyTypes() != null && !rule.getKeyTypes().isEmpty();
        boolean userAgentAllowed = isUserAgentAllowed(rule);

        if (!hasExplicitTypes || rule.getKeyTypes().contains(RateLimitProperties.KeyType.FINGERPRINT)) {
            String fingerprint = ctx.fingerprint();
            if (fingerprint == null || fingerprint.isBlank()) {
                fingerprint = fingerprintOrGenerate();
            }
            addKeyPart(keyParts, fingerprint, false);
        }

        if (!hasExplicitTypes || rule.getKeyTypes().contains(RateLimitProperties.KeyType.IDENTIFIER)) {
            for (String identifier : ctx.identifiers()) {
                addKeyPart(keyParts, identifier, true);
            }
        }

        if (hasExplicitTypes && rule.getKeyTypes().contains(RateLimitProperties.KeyType.IP)) {
            addKeyPart(keyParts, ctx.ip(), true);
        }

        if (hasExplicitTypes && rule.getKeyTypes().contains(RateLimitProperties.KeyType.USER_AGENT) && userAgentAllowed) {
            addKeyPart(keyParts, ctx.userAgent(), true);
        }

        if (keyParts.isEmpty()) {
            addKeyPart(keyParts, fingerprintOrGenerate(), false);
        }

        return keyParts;
    }

    private static void addKeyPart(List<String> keyParts, String value, boolean hashValue) {
        if (value == null) {
            return;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return;
        }
        keyParts.add(hashValue ? hash(trimmed) : trimmed);
    }

    private static boolean shouldTrackIncidents(RateLimitProperties.OnLimitAction action) {
        return action != RateLimitProperties.OnLimitAction.ALERT_ONLY;
    }

    private static boolean isUserAgentAllowed(RateLimitProperties.Rule rule) {
        if (rule.getKeyTypes() == null) {
            return false;
        }
        boolean hasIp = rule.getKeyTypes().contains(RateLimitProperties.KeyType.IP);
        boolean hasFingerprint = rule.getKeyTypes().contains(RateLimitProperties.KeyType.FINGERPRINT);
        return hasIp || hasFingerprint;
    }

    private boolean shouldAlertOnBlock(
            RedisTemplate<String, Long> redis,
            RateLimitProperties.Rule rule,
            String ruleKey,
            List<String> keyParts,
            long retryAfterSeconds
    ) {
        long alertTtl = Math.max(1, retryAfterSeconds);
        int cooldownSeconds = Math.max(0, rule.getAlertCooldownSeconds());
        if (cooldownSeconds > 0) {
            alertTtl = Math.max(alertTtl, cooldownSeconds);
        }
        if (!rule.isAlertOncePerBlock() && cooldownSeconds == 0) {
            return true;
        }
        return markAlertedForAnyKeyRedis(redis, ruleKey, keyParts, alertTtl);
    }

    private boolean shouldAlertOnNewBlock(
            RedisTemplate<String, Long> redis,
            RateLimitProperties.Rule rule,
            String ruleKey,
            List<String> keyParts,
            int blockSeconds
    ) {
        long alertTtl = Math.max(1, blockSeconds);
        int cooldownSeconds = Math.max(0, rule.getAlertCooldownSeconds());
        if (cooldownSeconds > 0) {
            alertTtl = Math.max(alertTtl, cooldownSeconds);
        }
        if (!rule.isAlertOncePerBlock() && cooldownSeconds == 0) {
            return true;
        }
        return markAlertedForAnyKeyRedis(redis, ruleKey, keyParts, alertTtl);
    }

    private boolean markAlertedForAnyKeyRedis(
            RedisTemplate<String, Long> redis,
            String ruleKey,
            List<String> keyParts,
            long ttlSeconds
    ) {
        for (String keyPart : keyParts) {
            if (markAlertedRedis(redis, ruleKey, keyPart, ttlSeconds)) {
                return true;
            }
        }
        return false;
    }

    private boolean markAlertedRedis(
            RedisTemplate<String, Long> redis,
            String ruleKey,
            String keyPart,
            long ttlSeconds
    ) {
        if (ttlSeconds <= 0) {
            return false;
        }
        String key = alertKey(ruleKey, keyPart);
        Boolean created = redis.opsForValue().setIfAbsent(key, 1L);
        if (Boolean.TRUE.equals(created)) {
            redis.expire(key, Duration.ofSeconds(ttlSeconds));
            return true;
        }
        return false;
    }

    private boolean shouldAlertOnBlockLocal(
            RateLimitProperties.Rule rule,
            String ruleKey,
            List<String> keyParts,
            long now,
            long retryAfterSeconds
    ) {
        long alertTtl = Math.max(1, retryAfterSeconds);
        int cooldownSeconds = Math.max(0, rule.getAlertCooldownSeconds());
        if (cooldownSeconds > 0) {
            alertTtl = Math.max(alertTtl, cooldownSeconds);
        }
        if (!rule.isAlertOncePerBlock() && cooldownSeconds == 0) {
            return true;
        }
        return markAlertedForAnyKeyLocal(ruleKey, keyParts, now, alertTtl);
    }

    private boolean shouldAlertOnNewBlockLocal(
            RateLimitProperties.Rule rule,
            String ruleKey,
            List<String> keyParts,
            long now,
            int blockSeconds
    ) {
        long alertTtl = Math.max(1, blockSeconds);
        int cooldownSeconds = Math.max(0, rule.getAlertCooldownSeconds());
        if (cooldownSeconds > 0) {
            alertTtl = Math.max(alertTtl, cooldownSeconds);
        }
        if (!rule.isAlertOncePerBlock() && cooldownSeconds == 0) {
            return true;
        }
        return markAlertedForAnyKeyLocal(ruleKey, keyParts, now, alertTtl);
    }

    private boolean markAlertedForAnyKeyLocal(
            String ruleKey,
            List<String> keyParts,
            long now,
            long ttlSeconds
    ) {
        for (String keyPart : keyParts) {
            if (markAlertedLocal(ruleKey, keyPart, now, ttlSeconds)) {
                return true;
            }
        }
        return false;
    }

    private boolean markAlertedLocal(
            String ruleKey,
            String keyPart,
            long now,
            long ttlSeconds
    ) {
        if (ttlSeconds <= 0) {
            return false;
        }
        String key = alertKey(ruleKey, keyPart);
        Counter existing = localAlerts.getIfPresent(key);
        if (existing != null && existing.expiresAt > now) {
            return false;
        }
        localAlerts.put(key, new Counter(1, now + (ttlSeconds * 1000L)));
        return true;
    }

    private void notifyIfAlert(
            RateLimitProperties.Rule rule,
            RateLimitContext ctx,
            RateLimitDecision decision
    ) {
        if (alertListener != null && decision != null && decision.alert()) {
            alertListener.onAlert(rule, ctx, decision);
        }
    }

    private RateLimitDecision applyRisk(
            RateLimitProperties.Rule rule,
            RateLimitContext ctx,
            RateLimitDecision decision,
            long incidentCount
    ) {
        if (decision == null) {
            return null;
        }
        RiskLevel level = evaluateRiskLevel(rule, ctx, decision, incidentCount);
        return decision.withRisk(level);
    }

    private RiskLevel evaluateRiskLevel(
            RateLimitProperties.Rule rule,
            RateLimitContext ctx,
            RateLimitDecision decision,
            long incidentCount
    ) {
        if (riskEvaluator == null || decision == null) {
            return decision == null ? RiskLevel.LOW : decision.risk();
        }
        return riskEvaluator.evaluate(rule, ctx, decision, incidentCount);
    }

    private static int applyRiskBlockMultiplier(
            int blockSeconds,
            RiskLevel riskLevel,
            RateLimitProperties.Rule rule
    ) {
        if (riskLevel == null || rule == null) {
            return Math.max(1, blockSeconds);
        }
        int multiplier = switch (riskLevel) {
            case HIGH -> rule.getRiskBlockMultiplierHigh();
            case MEDIUM -> rule.getRiskBlockMultiplierMedium();
            default -> 1;
        };
        int safeMultiplier = Math.max(1, multiplier);
        long scaled = (long) Math.max(1, blockSeconds) * safeMultiplier;
        return (int) Math.min(Integer.MAX_VALUE, scaled);
    }

    private long recordIncidentsRedis(
            RedisTemplate<String, Long> redis,
            String ruleKey,
            List<String> keyParts,
            int riskWindowSeconds
    ) {
        long max = 0;
        for (String keyPart : keyParts) {
            long count = incrementRedisCount(redis, ruleKey, keyPart, riskWindowSeconds);
            if (count > max) {
                max = count;
            }
        }
        return max;
    }

    private long getIncidentCountRedis(
            RedisTemplate<String, Long> redis,
            String ruleKey,
            List<String> keyParts
    ) {
        long max = 0;
        for (String keyPart : keyParts) {
            long count = readRedisCount(redis, ruleKey, keyPart);
            if (count > max) {
                max = count;
            }
        }
        return max;
    }

    private long recordIncidentsLocal(
            String ruleKey,
            List<String> keyParts,
            int riskWindowSeconds,
            long now
    ) {
        long max = 0;
        for (String keyPart : keyParts) {
            long count = incrementLocalCount(incidentKey(ruleKey, keyPart), riskWindowSeconds, now, localIncidents);
            if (count > max) {
                max = count;
            }
        }
        return max;
    }

    private long getIncidentCountLocal(String ruleKey, List<String> keyParts, long now) {
        long max = 0;
        for (String keyPart : keyParts) {
            String key = incidentKey(ruleKey, keyPart);
            Counter counter = localIncidents.getIfPresent(key);
            if (counter == null || counter.expiresAt <= now) {
                continue;
            }
            if (counter.count > max) {
                max = counter.count;
            }
        }
        return max;
    }

    private static long incrementLocalCount(
            String key,
            int windowSeconds,
            long now,
            Cache<String, Counter> cache
    ) {
        Counter counter = cache.asMap().compute(key, (k, existing) -> {
            if (existing == null || existing.expiresAt <= now) {
                return new Counter(1, now + (windowSeconds * 1000L));
            }
            existing.count += 1;
            return existing;
        });
        return counter.count;
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
