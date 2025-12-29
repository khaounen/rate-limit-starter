package com.khaounen.ratelimit.security.ratelimit;

public record RateLimitDecision(boolean allowed, long retryAfterSeconds) {

    public static RateLimitDecision allow() {
        return new RateLimitDecision(true, 0);
    }

    public static RateLimitDecision block(long retryAfterSeconds) {
        return new RateLimitDecision(false, Math.max(0, retryAfterSeconds));
    }
}
