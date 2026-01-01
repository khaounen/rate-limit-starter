package com.khaounen.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;

@FunctionalInterface
public interface DeviceAttestationResolver {
    boolean isAttested(HttpServletRequest request);
}
