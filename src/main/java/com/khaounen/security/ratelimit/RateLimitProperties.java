package com.khaounen.security.ratelimit;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.AntPathMatcher;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

@Data
@ConfigurationProperties(prefix = "rate-limit")
public class RateLimitProperties {

    private boolean enabled = false;
    private boolean applyDefaultToAll = false;
    private Rule defaults = new Rule();
    private List<Rule> endpoints = new ArrayList<>();

    private final AntPathMatcher matcher = new AntPathMatcher();

    public Optional<Rule> match(String path, String method) {
        String normalizedMethod = method == null ? "" : method.toUpperCase(Locale.ROOT);
        for (Rule rule : endpoints) {
            if (matcher.match(rule.getPath(), path) && rule.allowsMethod(normalizedMethod)) {
                return Optional.of(rule);
            }
        }
        if (applyDefaultToAll) {
            return Optional.of(defaults);
        }
        return Optional.empty();
    }

    @Data
    public static class Rule {
        private String path = "";
        private List<String> methods = new ArrayList<>();
        private int windowSeconds = 60;
        private int maxRequests = 60;
        private int blockSeconds = 600;
        private int authenticatedMultiplier = 1;
        private int mobileMultiplier = 1;
        private String key;
        private String keySuffix;
        private boolean applyAuthenticatedMultiplier = true;
        private OnLimitAction onLimitAction = OnLimitAction.BLOCK;
        private boolean alertOncePerBlock = true;
        private int alertCooldownSeconds = 0;
        private int riskScore = 0;
        private int riskMediumThreshold = 50;
        private int riskHighThreshold = 80;
        private int riskWindowSeconds = 86400;
        private int riskBlockMultiplierMedium = 1;
        private int riskBlockMultiplierHigh = 1;
        private List<KeyType> keyTypes = new ArrayList<>();
        private List<String> identifierParams = new ArrayList<>();
        private String identifierHeader;

        public boolean allowsMethod(String method) {
            if (methods == null || methods.isEmpty()) {
                return true;
            }
            return methods.stream().anyMatch(m -> m.equalsIgnoreCase(method));
        }
    }

    public enum KeyType {
        FINGERPRINT,
        IDENTIFIER,
        IP,
        USER_AGENT,
        VERIFIED_USER,
        MOBILE_ATTESTED
    }

    public enum OnLimitAction {
        BLOCK,
        CHALLENGE,
        ALERT,
        BLOCK_AND_ALERT,
        ALERT_ONLY
    }
}
