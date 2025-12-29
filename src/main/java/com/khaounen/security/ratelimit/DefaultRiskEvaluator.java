package com.khaounen.security.ratelimit;

public class DefaultRiskEvaluator implements RiskEvaluator {
    @Override
    public RiskLevel evaluate(
            RateLimitProperties.Rule rule,
            RateLimitContext context,
            RateLimitDecision decision,
            long incidentCount
    ) {
        int score = rule.getRiskScore();
        if (!decision.allowed()) {
            score += 40;
        }
        if (decision.captchaRequired()) {
            score += 20;
        }
        if (decision.alert()) {
            score += 20;
        }
        if (incidentCount > 0) {
            long capped = Math.min(incidentCount, 10);
            score += (int) (capped * 5);
        }

        if (score >= rule.getRiskHighThreshold()) {
            return RiskLevel.HIGH;
        }
        if (score >= rule.getRiskMediumThreshold()) {
            return RiskLevel.MEDIUM;
        }
        return RiskLevel.LOW;
    }
}
