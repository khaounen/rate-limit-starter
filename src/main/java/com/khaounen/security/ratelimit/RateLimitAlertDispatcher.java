package com.khaounen.security.ratelimit;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
public class RateLimitAlertDispatcher implements RateLimitAlertListener {

    private final RateLimitAlertProperties properties;
    private final ObjectProvider<ObjectMapper> objectMapperProvider;
    private final ObjectProvider<JavaMailSender> mailSenderProvider;

    public RateLimitAlertDispatcher(
            RateLimitAlertProperties properties,
            ObjectProvider<ObjectMapper> objectMapperProvider,
            ObjectProvider<JavaMailSender> mailSenderProvider
    ) {
        this.properties = properties;
        this.objectMapperProvider = objectMapperProvider;
        this.mailSenderProvider = mailSenderProvider;
    }

    @Override
    public void onAlert(RateLimitProperties.Rule rule, RateLimitContext context, RateLimitDecision decision) {
        if (properties == null) {
            return;
        }
        sendWebhook(rule, context, decision);
        sendSmtp(rule, context, decision);
    }

    private void sendWebhook(RateLimitProperties.Rule rule, RateLimitContext context, RateLimitDecision decision) {
        RateLimitAlertProperties.Webhook webhook = properties.getWebhook();
        if (webhook == null || !webhook.isEnabled() || webhook.getUrl() == null || webhook.getUrl().isBlank()) {
            return;
        }
        try {
            ObjectMapper mapper = objectMapperProvider.getIfAvailable(ObjectMapper::new);
            String payload = mapper.writeValueAsString(buildPayload(rule, context, decision, webhook.isIncludeContext()));
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofMillis(webhook.getConnectTimeoutMs()))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(webhook.getUrl()))
                    .timeout(java.time.Duration.ofMillis(webhook.getTimeoutMs()))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();
            client.sendAsync(request, HttpResponse.BodyHandlers.discarding());
        } catch (Exception ex) {
            log.warn("rate-limit webhook alert failed: {}", ex.getMessage());
        }
    }

    private void sendSmtp(RateLimitProperties.Rule rule, RateLimitContext context, RateLimitDecision decision) {
        RateLimitAlertProperties.Smtp smtp = properties.getSmtp();
        if (smtp == null || !smtp.isEnabled()) {
            return;
        }
        JavaMailSender sender = mailSenderProvider.getIfAvailable();
        if (sender == null || smtp.getFrom() == null || smtp.getFrom().isBlank() || smtp.getTo().isEmpty()) {
            return;
        }
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(smtp.getFrom());
            message.setTo(smtp.getTo().toArray(new String[0]));
            message.setSubject(smtp.getSubject());
            message.setText(buildMailBody(rule, context, decision, smtp.isIncludeContext()));
            sender.send(message);
        } catch (Exception ex) {
            log.warn("rate-limit smtp alert failed: {}", ex.getMessage());
        }
    }

    private Map<String, Object> buildPayload(
            RateLimitProperties.Rule rule,
            RateLimitContext context,
            RateLimitDecision decision,
            boolean includeContext
    ) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("timestamp", Instant.now().toString());
        payload.put("action", rule.getOnLimitAction().name());
        payload.put("risk", decision.risk().name());
        payload.put("ruleKey", rule.getKey());
        payload.put("rulePath", rule.getPath());
        if (includeContext) {
            Map<String, Object> ctx = new LinkedHashMap<>();
            ctx.put("authenticated", context.authenticated());
            ctx.put("ip", context.ip());
            ctx.put("userAgent", context.userAgent());
            ctx.put("fingerprint", context.fingerprint());
            ctx.put("identifiers", context.identifiers());
            payload.put("context", ctx);
        }
        return payload;
    }

    private String buildMailBody(
            RateLimitProperties.Rule rule,
            RateLimitContext context,
            RateLimitDecision decision,
            boolean includeContext
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("Rate limit alert\n");
        sb.append("timestamp: ").append(Instant.now()).append('\n');
        sb.append("action: ").append(rule.getOnLimitAction()).append('\n');
        sb.append("risk: ").append(decision.risk()).append('\n');
        sb.append("ruleKey: ").append(rule.getKey()).append('\n');
        sb.append("rulePath: ").append(rule.getPath()).append('\n');
        if (includeContext) {
            sb.append("authenticated: ").append(context.authenticated()).append('\n');
            sb.append("ip: ").append(context.ip()).append('\n');
            sb.append("userAgent: ").append(context.userAgent()).append('\n');
            sb.append("fingerprint: ").append(context.fingerprint()).append('\n');
            sb.append("identifiers: ").append(context.identifiers()).append('\n');
        }
        return sb.toString();
    }
}
