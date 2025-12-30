package com.khaounen.security.ratelimit;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DefaultRiskEvaluatorTest {

    @Test
    void calculatesRiskBasedOnScoreAndIncidents() {
        DefaultRiskEvaluator evaluator = new DefaultRiskEvaluator();
        RateLimitProperties.Rule rule = new RateLimitProperties.Rule();
        rule.setRiskScore(30);
        rule.setRiskMediumThreshold(50);
        rule.setRiskHighThreshold(80);

        RateLimitDecision allow = RateLimitDecision.allow();
        RiskLevel low = evaluator.evaluate(rule, ctx(), allow, 0);
        assertEquals(RiskLevel.LOW, low);

        RateLimitDecision block = RateLimitDecision.block(1);
        RiskLevel medium = evaluator.evaluate(rule, ctx(), block, 0);
        assertEquals(RiskLevel.MEDIUM, medium);

        RiskLevel high = evaluator.evaluate(rule, ctx(), block, 3);
        assertEquals(RiskLevel.HIGH, high);
    }

    private static RateLimitContext ctx() {
        return new RateLimitContext(false, "fp", "ip", "ua", List.of("id"));
    }
}
