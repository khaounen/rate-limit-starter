package com.khaounen.ratelimit.config;

import com.khaounen.ratelimit.security.ratelimit.FingerprintStrategy;
import com.khaounen.ratelimit.utils.IpUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class RequestContextFilter extends OncePerRequestFilter {

    private final FingerprintStrategy fingerprintStrategy;

    public RequestContextFilter(FingerprintStrategy fingerprintStrategy) {
        this.fingerprintStrategy = fingerprintStrategy;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            RequestContext.setIp(IpUtils.resolveIp(request));
            RequestContext.setUserAgent(request.getHeader("User-Agent"));
            RequestContext.setFingerprint(fingerprintStrategy.generate(request));
            filterChain.doFilter(request, response);
        } finally {
            RequestContext.clear();
        }
    }
}
