package com.khaounen.ratelimit.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;

public interface FingerprintStrategy {
    String generate(HttpServletRequest request);
}
