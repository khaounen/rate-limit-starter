package com.khaounen.security.ratelimit;

public interface RateLimitAlertListener {
    void onAlert(RateLimitProperties.Rule rule, RateLimitContext context, RateLimitDecision decision);
}
