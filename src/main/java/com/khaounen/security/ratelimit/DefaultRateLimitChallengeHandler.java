package com.khaounen.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class DefaultRateLimitChallengeHandler implements RateLimitChallengeHandler {
    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            RateLimitDecision decision
    ) throws IOException {
        response.setStatus(403);
        response.setContentType("text/plain");
        response.getWriter().write("Captcha required.");
    }
}
