package com.khaounen.security.ratelimit;

public record RateLimitDecision(
        boolean allowed,
        long retryAfterSeconds,
        RiskLevel risk,
        boolean captchaRequired,
        boolean alert
) {

    public static RateLimitDecision allow() {
        return new RateLimitDecision(true, 0, RiskLevel.LOW, false, false);
    }

    public static RateLimitDecision block(long retryAfterSeconds) {
        return new RateLimitDecision(false, Math.max(0, retryAfterSeconds), RiskLevel.HIGH, false, false);
    }

    public static RateLimitDecision challenge() {
        return new RateLimitDecision(false, 0, RiskLevel.MEDIUM, true, false);
    }

    public static RateLimitDecision alertDecision() {
        return new RateLimitDecision(true, 0, RiskLevel.MEDIUM, false, true);
    }

    public RateLimitDecision withRisk(RiskLevel riskLevel) {
        if (riskLevel == null || riskLevel == risk) {
            return this;
        }
        return new RateLimitDecision(allowed, retryAfterSeconds, riskLevel, captchaRequired, alert);
    }

    public RateLimitDecision withAlert(boolean enabled) {
        if (alert == enabled) {
            return this;
        }
        return new RateLimitDecision(allowed, retryAfterSeconds, risk, captchaRequired, enabled);
    }
}
