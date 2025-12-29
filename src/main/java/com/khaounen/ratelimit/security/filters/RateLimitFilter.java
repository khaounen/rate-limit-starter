package com.khaounen.ratelimit.security.filters;

import com.khaounen.ratelimit.security.ratelimit.RateLimitDecision;
import com.khaounen.ratelimit.security.ratelimit.RateLimitProperties;
import com.khaounen.ratelimit.security.ratelimit.RateLimitService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StreamUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.databind.ObjectMapper;

public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitProperties properties;
    private final RateLimitService service;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(
            RateLimitProperties properties,
            RateLimitService service,
            ObjectMapper objectMapper
    ) {
        this.properties = properties;
        this.service = service;
        this.objectMapper = objectMapper;
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

        boolean authenticated = isAuthenticated();
        RateLimitProperties.Rule rule = ruleOpt.get();
        HttpServletRequest effectiveRequest = request;
        String identifier = null;
        if (shouldReadBody(request, rule)) {
            byte[] body = StreamUtils.copyToByteArray(request.getInputStream());
            effectiveRequest = new CachedBodyRequest(request, body);
            identifier = extractIdentifier(effectiveRequest, rule, body);
        } else {
            identifier = extractIdentifier(request, rule, null);
        }
        RateLimitDecision decision = service.check(rule, authenticated, identifier);
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

    private boolean isAuthenticated() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }
        Object principal = auth.getPrincipal();
        return principal != null && !"anonymousUser".equals(principal);
    }

    private String extractIdentifier(HttpServletRequest request, RateLimitProperties.Rule rule, byte[] body) {
        String header = rule.getIdentifierHeader();
        if (header != null && !header.isBlank()) {
            String value = request.getHeader(header);
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        if (rule.getIdentifierParams() == null || rule.getIdentifierParams().isEmpty()) {
            return null;
        }
        for (String param : rule.getIdentifierParams()) {
            String value = request.getParameter(param);
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        if (body != null && body.length > 0) {
            return extractFromJsonBody(body, rule.getIdentifierParams());
        }
        return null;
    }

    private boolean shouldReadBody(HttpServletRequest request, RateLimitProperties.Rule rule) {
        if (rule.getIdentifierParams() == null || rule.getIdentifierParams().isEmpty()) {
            return false;
        }
        String contentType = request.getContentType();
        return contentType != null && contentType.startsWith(MediaType.APPLICATION_JSON_VALUE);
    }

    private String extractFromJsonBody(byte[] body, Iterable<String> fields) {
        try {
            String payloadText = new String(body, StandardCharsets.UTF_8);
            if (payloadText.isBlank()) {
                return null;
            }
            Map<String, Object> payload = objectMapper.readValue(payloadText, Map.class);
            for (String field : fields) {
                Object value = payload.get(field);
                if (value != null) {
                    String text = value.toString().trim();
                    if (!text.isEmpty()) {
                        return text;
                    }
                }
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
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
