package com.khaounen.security.ratelimit;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "rate-limit.alert")
public class RateLimitAlertProperties {

    private Webhook webhook = new Webhook();
    private Smtp smtp = new Smtp();

    @Data
    public static class Webhook {
        private boolean enabled = false;
        private String url;
        private int connectTimeoutMs = 1000;
        private int timeoutMs = 2000;
        private boolean includeContext = true;
    }

    @Data
    public static class Smtp {
        private boolean enabled = false;
        private String from;
        private List<String> to = new ArrayList<>();
        private String subject = "Rate limit alert";
        private boolean includeContext = true;
    }
}
