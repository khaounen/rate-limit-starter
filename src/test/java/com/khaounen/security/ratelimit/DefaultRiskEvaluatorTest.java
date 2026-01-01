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

    @Test
    void respectsCustomThresholdsAndBaseScore() {
        DefaultRiskEvaluator evaluator = new DefaultRiskEvaluator();
        RateLimitProperties.Rule rule = new RateLimitProperties.Rule();
        rule.setRiskScore(60);
        rule.setRiskMediumThreshold(40);
        rule.setRiskHighThreshold(70);

        RiskLevel medium = evaluator.evaluate(rule, ctx(), RateLimitDecision.allow(), 0);
        assertEquals(RiskLevel.MEDIUM, medium);

        RiskLevel high = evaluator.evaluate(rule, ctx(), RateLimitDecision.block(1), 0);
        assertEquals(RiskLevel.HIGH, high);
    }

    @Test
    void incidentCountContributesToRiskScore() {
        DefaultRiskEvaluator evaluator = new DefaultRiskEvaluator();
        RateLimitProperties.Rule rule = new RateLimitProperties.Rule();
        rule.setRiskScore(0);
        rule.setRiskMediumThreshold(25);
        rule.setRiskHighThreshold(60);

        RiskLevel medium = evaluator.evaluate(rule, ctx(), RateLimitDecision.allow(), 6);
        assertEquals(RiskLevel.MEDIUM, medium);
    }

    @Test
    void blockAndAlertDoesNotAddAlertRiskByDefault() {
        DefaultRiskEvaluator evaluator = new DefaultRiskEvaluator();
        RateLimitProperties.Rule rule = new RateLimitProperties.Rule();
        rule.setRiskScore(0);
        rule.setRiskMediumThreshold(50);
        rule.setRiskHighThreshold(80);

        RateLimitDecision decision = RateLimitDecision.block(1).withAlert(true);
        RiskLevel level = evaluator.evaluate(rule, ctx(), decision, 0);
        assertEquals(RiskLevel.LOW, level);
    }

    private static RateLimitContext ctx() {
        return new RateLimitContext(false, false, false, "fp", "ip", "ua", List.of("id"));
    }
}
