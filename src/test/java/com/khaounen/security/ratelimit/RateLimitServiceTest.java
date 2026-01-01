package com.khaounen.security.ratelimit;

import com.khaounen.config.RequestContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimitServiceTest {

    @Test
    void alertCooldownPreventsRepeatedAlertsWithinWindow() throws Exception {
        AtomicInteger alerts = new AtomicInteger();
        RateLimitService service = buildService(alerts);
        RateLimitProperties.Rule rule = baseRule();
        rule.setMaxRequests(1);
        rule.setWindowSeconds(1);
        rule.setBlockSeconds(1);
        rule.setOnLimitAction(RateLimitProperties.OnLimitAction.BLOCK_AND_ALERT);
        rule.setAlertOncePerBlock(true);
        rule.setAlertCooldownSeconds(3);

        RateLimitContext ctx = new RateLimitContext(false, false, false, "fp", null, null, List.of());

        RateLimitDecision first = service.check(rule, ctx);
        assertTrue(first.allowed());
        assertEquals(0, alerts.get());

        RateLimitDecision second = service.check(rule, ctx);
        assertFalse(second.allowed());
        assertTrue(second.alert());
        assertEquals(1, alerts.get());

        RateLimitDecision third = service.check(rule, ctx);
        assertFalse(third.allowed());
        assertFalse(third.alert());
        assertEquals(1, alerts.get());

        Thread.sleep(1100);

        RateLimitDecision fourth = service.check(rule, ctx);
        assertTrue(fourth.allowed());

        RateLimitDecision fifth = service.check(rule, ctx);
        assertFalse(fifth.allowed());
        assertFalse(fifth.alert());
        assertEquals(1, alerts.get());
    }

    @Test
    void alertCooldownExpiresAllowsNewAlert() throws Exception {
        AtomicInteger alerts = new AtomicInteger();
        RateLimitService service = buildService(alerts);
        RateLimitProperties.Rule rule = baseRule();
        rule.setMaxRequests(1);
        rule.setWindowSeconds(1);
        rule.setBlockSeconds(1);
        rule.setOnLimitAction(RateLimitProperties.OnLimitAction.BLOCK_AND_ALERT);
        rule.setAlertOncePerBlock(true);
        rule.setAlertCooldownSeconds(1);

        RateLimitContext ctx = new RateLimitContext(false, false, false, "fp", null, null, List.of());

        service.check(rule, ctx);
        RateLimitDecision blocked = service.check(rule, ctx);
        assertTrue(blocked.alert());
        assertEquals(1, alerts.get());

        Thread.sleep(1100);

        service.check(rule, ctx);
        RateLimitDecision blockedAgain = service.check(rule, ctx);
        assertTrue(blockedAgain.alert());
        assertEquals(2, alerts.get());
    }

    @Test
    void userAgentKeyIsIgnoredWithoutIpOrFingerprint() {
        AtomicInteger alerts = new AtomicInteger();
        RateLimitService service = buildService(alerts);
        RateLimitProperties.Rule rule = baseRule();
        rule.setMaxRequests(1);
        rule.setWindowSeconds(60);
        rule.setBlockSeconds(60);
        rule.setOnLimitAction(RateLimitProperties.OnLimitAction.BLOCK);
        rule.setKeyTypes(List.of(RateLimitProperties.KeyType.USER_AGENT));

        RateLimitContext ctx = new RateLimitContext(false, false, false, null, null, "ua", List.of());

        try {
            RequestContext.setFingerprint("fp1");
            RateLimitDecision first = service.check(rule, ctx);
            assertTrue(first.allowed());

            RequestContext.setFingerprint("fp2");
            RateLimitDecision second = service.check(rule, ctx);
            assertTrue(second.allowed());
        } finally {
            RequestContext.clear();
        }
    }

    @Test
    void authenticatedMultiplierRequiresVerifiedWhenConfigured() {
        RateLimitService service = buildService(new AtomicInteger());
        RateLimitProperties.Rule rule = baseRule();
        rule.setMaxRequests(1);
        rule.setAuthenticatedMultiplier(2);
        rule.setKeyTypes(List.of(RateLimitProperties.KeyType.FINGERPRINT, RateLimitProperties.KeyType.VERIFIED_USER));

        RateLimitContext unverified = new RateLimitContext(true, false, false, "fp-unverified", null, null, List.of());
        RateLimitDecision first = service.check(rule, unverified);
        assertTrue(first.allowed());
        RateLimitDecision second = service.check(rule, unverified);
        assertFalse(second.allowed());

        RateLimitContext verified = new RateLimitContext(true, true, false, "fp-verified", null, null, List.of());
        RateLimitDecision third = service.check(rule, verified);
        assertTrue(third.allowed());
        RateLimitDecision fourth = service.check(rule, verified);
        assertTrue(fourth.allowed());
        RateLimitDecision fifth = service.check(rule, verified);
        assertFalse(fifth.allowed());
    }

    @Test
    void mobileMultiplierAppliesOnlyWhenAttestedAndEnabled() {
        RateLimitService service = buildService(new AtomicInteger());
        RateLimitProperties.Rule rule = baseRule();
        rule.setMaxRequests(1);
        rule.setMobileMultiplier(3);
        rule.setKeyTypes(List.of(RateLimitProperties.KeyType.FINGERPRINT, RateLimitProperties.KeyType.MOBILE_ATTESTED));

        RateLimitContext unattested = new RateLimitContext(false, false, false, "fp-unattested", null, null, List.of());
        RateLimitDecision first = service.check(rule, unattested);
        assertTrue(first.allowed());
        RateLimitDecision second = service.check(rule, unattested);
        assertFalse(second.allowed());

        RateLimitContext attested = new RateLimitContext(false, false, true, "fp-attested", null, null, List.of());
        RateLimitDecision third = service.check(rule, attested);
        assertTrue(third.allowed());
        RateLimitDecision fourth = service.check(rule, attested);
        assertTrue(fourth.allowed());
        RateLimitDecision fifth = service.check(rule, attested);
        assertTrue(fifth.allowed());
        RateLimitDecision sixth = service.check(rule, attested);
        assertFalse(sixth.allowed());
    }

    private static RateLimitService buildService(AtomicInteger alerts) {
        ObjectProvider<org.springframework.data.redis.core.RedisTemplate<String, Long>> redisProvider =
                new SimpleObjectProvider<>(null);
        FingerprintStrategy fingerprintStrategy = request -> "fp";
        RateLimitAlertListener alertListener = (rule, ctx, decision) -> alerts.incrementAndGet();
        RiskEvaluator riskEvaluator = (rule, ctx, decision, incidentCount) -> decision.risk();
        return new RateLimitService(redisProvider, fingerprintStrategy, alertListener, riskEvaluator);
    }

    private static RateLimitProperties.Rule baseRule() {
        RateLimitProperties.Rule rule = new RateLimitProperties.Rule();
        rule.setPath("/test");
        return rule;
    }

    private static final class SimpleObjectProvider<T> implements ObjectProvider<T> {
        private final T instance;

        private SimpleObjectProvider(T instance) {
            this.instance = instance;
        }

        @Override
        public T getObject(Object... args) {
            if (instance == null) {
                throw new IllegalStateException("No object available");
            }
            return instance;
        }

        @Override
        public T getObject() {
            return getObject(new Object[0]);
        }

        @Override
        public T getIfAvailable() {
            return instance;
        }

        @Override
        public T getIfAvailable(Supplier<T> supplier) {
            return instance != null ? instance : supplier.get();
        }

        @Override
        public T getIfUnique() {
            return instance;
        }

        @Override
        public T getIfUnique(Supplier<T> supplier) {
            return instance != null ? instance : supplier.get();
        }

        @Override
        public Stream<T> stream() {
            return instance == null ? Stream.empty() : Stream.of(instance);
        }

        @Override
        public Stream<T> orderedStream() {
            return stream();
        }
    }
}
