package com.khaounen.security.ratelimit;

public interface RiskEvaluator {
    RiskLevel evaluate(
            RateLimitProperties.Rule rule,
            RateLimitContext context,
            RateLimitDecision decision,
            long incidentCount
    );
}
