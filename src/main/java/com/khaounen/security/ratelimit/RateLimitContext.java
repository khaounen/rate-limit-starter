package com.khaounen.security.ratelimit;

import java.util.List;

public record RateLimitContext(
        boolean authenticated,
        boolean verified,
        boolean mobileAttested,
        String fingerprint,
        String ip,
        String userAgent,
        List<String> identifiers
) {
    public RateLimitContext {
        identifiers = identifiers == null ? List.of() : List.copyOf(identifiers);
    }
}
