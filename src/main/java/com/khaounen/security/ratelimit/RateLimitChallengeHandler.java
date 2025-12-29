package com.khaounen.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface RateLimitChallengeHandler {
    void handle(HttpServletRequest request, HttpServletResponse response, RateLimitDecision decision) throws IOException;
}
