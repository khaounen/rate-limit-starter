package com.khaounen.security.filters;

import com.khaounen.config.RequestContext;
import com.khaounen.security.ratelimit.RateLimitChallengeHandler;
import com.khaounen.security.ratelimit.RateLimitContext;
import com.khaounen.security.ratelimit.RateLimitDecision;
import com.khaounen.security.ratelimit.RateLimitProperties;
import com.khaounen.security.ratelimit.RateLimitService;
import com.khaounen.security.ratelimit.DeviceAttestationResolver;
import com.khaounen.security.ratelimit.UserVerificationResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StreamUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.databind.ObjectMapper;

public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitProperties properties;
    private final RateLimitService service;
    private final ObjectMapper objectMapper;
    private final RateLimitChallengeHandler challengeHandler;
    private final UserVerificationResolver userVerificationResolver;
    private final DeviceAttestationResolver deviceAttestationResolver;

    public RateLimitFilter(
            RateLimitProperties properties,
            RateLimitService service,
            ObjectMapper objectMapper,
            RateLimitChallengeHandler challengeHandler,
            UserVerificationResolver userVerificationResolver,
            DeviceAttestationResolver deviceAttestationResolver
    ) {
        this.properties = properties;
        this.service = service;
        this.objectMapper = objectMapper;
        this.challengeHandler = challengeHandler;
        this.userVerificationResolver = userVerificationResolver;
        this.deviceAttestationResolver = deviceAttestationResolver;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (!properties.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        String method = request.getMethod();
        Optional<RateLimitProperties.Rule> ruleOpt = properties.match(path, method);
        if (ruleOpt.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean authenticated = isAuthenticated(auth);
        boolean verified = isVerified(auth, request);
        boolean mobileAttested = isMobileAttested(request);
        RateLimitProperties.Rule rule = ruleOpt.get();
        HttpServletRequest effectiveRequest = request;
        List<String> identifiers = List.of();
        if (shouldReadBody(request, rule)) {
            byte[] body = StreamUtils.copyToByteArray(request.getInputStream());
            effectiveRequest = new CachedBodyRequest(request, body);
            identifiers = extractIdentifiers(effectiveRequest, rule, body);
        } else {
            identifiers = extractIdentifiers(request, rule, null);
        }
        RateLimitContext ctx = new RateLimitContext(
                authenticated,
                verified,
                mobileAttested,
                resolveFingerprint(auth, authenticated),
                RequestContext.getIp(),
                RequestContext.getUserAgent(),
                identifiers
        );
        RateLimitDecision decision = service.check(rule, ctx);
        response.setHeader("X-RateLimit-Risk", decision.risk().name());
        if (decision.alert()) {
            response.setHeader("X-RateLimit-Alert", "true");
        }
        if (decision.captchaRequired()) {
            response.setHeader("X-RateLimit-Challenge", "captcha");
            challengeHandler.handle(effectiveRequest, response, decision);
            return;
        }
        if (!decision.allowed()) {
            response.setStatus(429);
            response.setHeader("Retry-After", String.valueOf(decision.retryAfterSeconds()));
            response.setContentType("text/plain");
            long retryAfterSeconds = decision.retryAfterSeconds();
            long retryAfterMinutes = Math.max(1, (retryAfterSeconds + 59) / 60);
            response.getWriter().write(
                    "Too Many Requests. Try again in " + retryAfterMinutes + " minute(s)."
            );
            return;
        }

        filterChain.doFilter(effectiveRequest, response);
    }

    private boolean isVerified(Authentication auth, HttpServletRequest request) {
        if (userVerificationResolver == null) {
            return false;
        }
        return userVerificationResolver.isVerified(auth, request);
    }

    private boolean isMobileAttested(HttpServletRequest request) {
        if (deviceAttestationResolver == null) {
            return false;
        }
        return deviceAttestationResolver.isAttested(request);
    }

    private boolean isAuthenticated(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }
        Object principal = auth.getPrincipal();
        return principal != null && !"anonymousUser".equals(principal);
    }

    private String resolveFingerprint(Authentication auth, boolean authenticated) {
        if (!authenticated || auth == null) {
            return RequestContext.getFingerprint();
        }
        String authName = auth.getName();
        if (authName != null && !authName.isBlank()) {
            return authName;
        }
        Object principal = auth.getPrincipal();
        if (principal == null || "anonymousUser".equals(principal)) {
            return RequestContext.getFingerprint();
        }
        if (principal instanceof UserDetails userDetails) {
            return userDetails.getUsername();
        }
        if (principal instanceof Principal javaPrincipal) {
            return javaPrincipal.getName();
        }
        if (principal instanceof String text) {
            return text;
        }
        String value = principal.toString();
        return value == null || value.isBlank() ? RequestContext.getFingerprint() : value;
    }

    private List<String> extractIdentifiers(HttpServletRequest request, RateLimitProperties.Rule rule, byte[] body) {
        LinkedHashSet<String> identifiers = new LinkedHashSet<>();
        String header = rule.getIdentifierHeader();
        if (header != null && !header.isBlank()) {
            String value = request.getHeader(header);
            if (value != null && !value.isBlank()) {
                identifiers.add(value.trim());
            }
        }
        if (rule.getIdentifierParams() == null || rule.getIdentifierParams().isEmpty()) {
            return new ArrayList<>(identifiers);
        }
        for (String param : rule.getIdentifierParams()) {
            String value = request.getParameter(param);
            if (value != null && !value.isBlank()) {
                identifiers.add(value.trim());
            }
        }
        if (body != null && body.length > 0) {
            identifiers.addAll(extractFromJsonBody(body, rule.getIdentifierParams()));
        }
        return new ArrayList<>(identifiers);
    }

    private boolean shouldReadBody(HttpServletRequest request, RateLimitProperties.Rule rule) {
        if (rule.getIdentifierParams() == null || rule.getIdentifierParams().isEmpty()) {
            return false;
        }
        String contentType = request.getContentType();
        return contentType != null && contentType.startsWith(MediaType.APPLICATION_JSON_VALUE);
    }

    private List<String> extractFromJsonBody(byte[] body, Iterable<String> fields) {
        try {
            String payloadText = new String(body, StandardCharsets.UTF_8);
            if (payloadText.isBlank()) {
                return List.of();
            }
            Map<String, Object> payload = objectMapper.readValue(payloadText, Map.class);
            List<String> identifiers = new ArrayList<>();
            for (String field : fields) {
                Object value = payload.get(field);
                if (value != null) {
                    if (value instanceof Iterable<?> items) {
                        for (Object item : items) {
                            addIdentifier(identifiers, item);
                        }
                    } else {
                        addIdentifier(identifiers, value);
                    }
                }
            }
            return identifiers;
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private static void addIdentifier(List<String> identifiers, Object value) {
        String text = value.toString().trim();
        if (!text.isEmpty()) {
            identifiers.add(text);
        }
    }

    private static class CachedBodyRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        private CachedBodyRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body != null ? body : new byte[0];
        }

        @Override
        public ServletInputStream getInputStream() {
            return new ServletInputStream() {
                private int index = 0;

                @Override
                public boolean isFinished() {
                    return index >= body.length;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener readListener) {
                    // No async support required.
                }

                @Override
                public int read() {
                    if (isFinished()) {
                        return -1;
                    }
                    return body[index++] & 0xff;
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
        }
    }
}
