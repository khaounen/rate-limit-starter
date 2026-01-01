package com.khaounen.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

@FunctionalInterface
public interface UserVerificationResolver {
    boolean isVerified(Authentication authentication, HttpServletRequest request);
}
