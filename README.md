# rate-limit-starter

Spring Boot rate-limit starter with fingerprint-based throttling, Redis TTL counters, and per-endpoint rules.

## Features
- Per-endpoint rate limits with Ant-style path patterns.
- Multi-key limits (fingerprint, identifiers, IP, user-agent).
- Redis-backed counters with Caffeine in-memory fallback.
- Request context filter to capture IP and user-agent.
- Risk-aware decisions and on-limit actions (block, challenge, alert).
- Alert listeners via webhook HTTP POST or SMTP email.

## Compatibility
- Java 17+
- Spring Boot 3.x

## Installation
```gradle
dependencies {
    implementation "com.khaounen:rate-limit-starter:1.0.1"
}
```

## Usage
The starter auto-configures itself when on the classpath.

Configure limits in `application.yml`:

```yaml
rate-limit:
  enabled: true
  apply-default-to-all: true
  defaults:
    window-seconds: 60
    max-requests: 300
    block-seconds: 300
    authenticated-multiplier: 3
  endpoints:
    - path: /users/login
      window-seconds: 60
      max-requests: 5
      block-seconds: 900
      on-limit-action: ALERT
      key-types: [FINGERPRINT, IDENTIFIER, IP]
      identifier-params:
        - username
```

## Filter Order
The starter registers two filters in the Spring Security chain:
- `RequestContextFilter`: runs early (before auth) to capture IP and User-Agent.
- `RateLimitFilter`: runs after auth so it can apply `authenticated-multiplier`.

This ordering ensures the fingerprint is always available, and authenticated users can benefit from higher limits.
When a request is authenticated, the rate-limit fingerprint is derived from `Authentication.getName()` (e.g., JWT `sub`),
falling back to the request fingerprint for anonymous traffic.

## Configuration Reference

Top-level:
- `rate-limit.enabled` (boolean): enable or disable the limiter.
- `rate-limit.apply-default-to-all` (boolean): apply `defaults` to all requests not explicitly listed.
- `rate-limit.defaults`: base rule applied when `apply-default-to-all` is true.
- `rate-limit.endpoints`: list of endpoint-specific rules.

Rule fields:
- `path` (string): Ant-style path pattern.
- `methods` (list): restrict by HTTP method. Empty = all.
- `window-seconds` (int): time window in seconds.
- `max-requests` (int): max requests per window.
- `block-seconds` (int): block duration after exceeding the limit.
- `authenticated-multiplier` (int): multiplier when user is authenticated.
- `mobile-multiplier` (int): multiplier when device attestation is valid.
- `apply-authenticated-multiplier` (boolean): disable multiplier for sensitive endpoints (OTP/signup).
- `on-limit-action` (string): `BLOCK` (default), `CHALLENGE`, `ALERT`, `BLOCK_AND_ALERT`, or `ALERT_ONLY`.
- `alert-once-per-block` (boolean): when `BLOCK_AND_ALERT`, emit only one alert per block window (default true).
- `alert-cooldown-seconds` (int): minimum time between alerts per key; overrides block window if larger.
- `risk-score` (int): base score added for this endpoint (e.g. login/otp).
- `risk-medium-threshold` (int): score threshold for `MEDIUM`.
- `risk-high-threshold` (int): score threshold for `HIGH`.
- `risk-window-seconds` (int): rolling window for incident count aggregation.
- `key-types` (list): any of `FINGERPRINT`, `IDENTIFIER`, `IP`, `USER_AGENT`, `VERIFIED_USER`, `MOBILE_ATTESTED`.
- `identifier-params` (list): request params or JSON fields used as secondary key (email/phone/username).
- `identifier-header` (string): header used as secondary key.
- `key` (string): custom Redis key prefix for the rule.
- `key-suffix` (string): suffix appended to the key (useful for grouping).

Notes:
- Counters use `rate:count:*` with TTL = `window-seconds`.
- Blocks use `rate:block:*` with TTL = `block-seconds`.
- Redis is used when a RedisTemplate bean is present; otherwise Caffeine in-memory caches are used.
- Caffeine entries expire per entry (window or block duration), preventing unbounded growth in local mode.

## Key Types Behavior
- If `key-types` is empty, defaults to `FINGERPRINT` + `IDENTIFIER` (if any).
- Each key type is evaluated separately (OR): any key exceeding the limit blocks/alerts the request.
- `USER_AGENT` is ignored unless `IP` or `FINGERPRINT` is also present to avoid false positives from shared UAs.
- The default fingerprint already mixes IP + User-Agent (see `DefaultFingerPrint`), so you usually do not need `USER_AGENT` as a key.
- `VERIFIED_USER` makes `authenticated-multiplier` apply only when the user is verified.
- `MOBILE_ATTESTED` makes `mobile-multiplier` apply only when device attestation succeeds.

Examples:
```yaml
rate-limit:
  endpoints:
    # Default behavior: fingerprint + identifier
    - path: /users/login
      identifier-params: [username]

    # Explicit multi-key: IP + identifier
    - path: /users/send-otp
      key-types: [IP, IDENTIFIER]
      identifier-params: [phone]

    # UA counted only if IP or fingerprint is also present
    - path: /abuse/signal
      key-types: [FINGERPRINT, USER_AGENT]

    # Auth multiplier only for verified users
    - path: /users/profile
      authenticated-multiplier: 2
      key-types: [FINGERPRINT, VERIFIED_USER]

    # Mobile attestation multiplier
    - path: /mobile/feed
      mobile-multiplier: 3
      key-types: [FINGERPRINT, MOBILE_ATTESTED]
```

## Custom Fingerprint
Provide your own strategy:

```java
@Bean
public FingerprintStrategy fingerprintStrategy() {
    return request -> "custom-fingerprint";
}
```

## User Verification / Device Attestation
To apply multipliers only to verified users or attested devices, provide resolvers:

```java
@Bean
public UserVerificationResolver userVerificationResolver() {
    return (auth, request) -> {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }
        Object principal = auth.getPrincipal();
        if (principal instanceof org.springframework.security.oauth2.jwt.Jwt jwt) {
            Object verified = jwt.getClaims().get("verified");
            return Boolean.TRUE.equals(verified);
        }
        return false;
    };
}

@Bean
public DeviceAttestationResolver deviceAttestationResolver(AttestationService attestationService) {
    return request -> {
        String token = request.getHeader("X-App-Attestation");
        return token != null && attestationService.verify(token);
    };
}
```

## Alerting (Webhook / SMTP)
Alerts fire when `on-limit-action: ALERT` is configured on a rule.

Webhook:
```yaml
rate-limit:
  alert:
    webhook:
      enabled: true
      url: https://your-webhook.example/ratelimit
      connect-timeout-ms: 1000
      timeout-ms: 2000
      include-context: true
  endpoints:
    - path: /users/login
      on-limit-action: BLOCK_AND_ALERT
      alert-once-per-block: true
      alert-cooldown-seconds: 900
```

SMTP:
```yaml
rate-limit:
  alert:
    smtp:
      enabled: true
      from: "security@your-domain.com"
      to:
        - "ops@your-domain.com"
      subject: "Rate limit alert"
      include-context: true
spring:
  mail:
    host: smtp.example.com
    port: 587
    username: your-user
    password: your-pass
    properties:
      mail.smtp.auth: true
      mail.smtp.starttls.enable: true
```

## Challenge Handling
For `on-limit-action: CHALLENGE`, the default handler returns a `403` with "Captcha required.".
You can override this behavior by providing a `RateLimitChallengeHandler` bean.

Example (custom captcha response):
```java
@Bean
public RateLimitChallengeHandler rateLimitChallengeHandler(CaptchaService captchaService) {
    return (request, response, decision) -> {
        String token = request.getHeader("X-Captcha-Token");
        if (token != null && captchaService.verify(token)) {
            return;
        }
        response.setStatus(403);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"captcha_required\"}");
    };
}
```

Example (Cloudflare Turnstile backend verify):
```java
@Service
public class TurnstileCaptchaService implements CaptchaService {
    private final RestTemplate restTemplate;
    private final String secret;

    public TurnstileCaptchaService(
            RestTemplateBuilder restTemplateBuilder,
            @Value("${captcha.turnstile.secret}") String secret
    ) {
        this.restTemplate = restTemplateBuilder.build();
        this.secret = secret;
    }

    @Override
    public boolean verify(String token) {
        String url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("secret", secret);
        form.add("response", token);
        TurnstileResponse response = restTemplate.postForObject(url, form, TurnstileResponse.class);
        return response != null && response.success();
    }

    private record TurnstileResponse(boolean success) {}
}
```

Example (Cloudflare Turnstile end-to-end):

Backend config:
```yaml
captcha:
  turnstile:
    secret: ${TURNSTILE_SECRET}
```

Backend verify + challenge handler:
```java
@Bean
public RateLimitChallengeHandler rateLimitChallengeHandler(CaptchaService captchaService) {
    return (request, response, decision) -> {
        String token = request.getHeader("X-Captcha-Token");
        if (token != null && captchaService.verify(token)) {
            return;
        }
        response.setStatus(403);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"captcha_required\"}");
    };
}

@Service
public class TurnstileCaptchaService implements CaptchaService {
    private final RestTemplate restTemplate;
    private final String secret;

    public TurnstileCaptchaService(
            RestTemplateBuilder restTemplateBuilder,
            @Value("${captcha.turnstile.secret}") String secret
    ) {
        this.restTemplate = restTemplateBuilder.build();
        this.secret = secret;
    }

    @Override
    public boolean verify(String token) {
        String url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("secret", secret);
        form.add("response", token);
        TurnstileResponse response = restTemplate.postForObject(url, form, TurnstileResponse.class);
        return response != null && response.success();
    }

    private record TurnstileResponse(boolean success) {}
}
```

Frontend example (plain HTML/JS):
```html
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
<button id="submit">Submit</button>
<script>
  document.getElementById("submit").addEventListener("click", async () => {
    const token = window.turnstile.getResponse();
    const res = await fetch("/your/api/endpoint", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Captcha-Token": token
      },
      body: JSON.stringify({ hello: "world" })
    });
    if (res.status === 403) {
      window.turnstile.reset();
    }
  });
</script>
```

## Risk Evaluation
The starter computes a risk score per decision using a `RiskEvaluator`. The default evaluator:
- adds a base `risk-score` from the rule
- increases score on block/challenge/alert
- increases score when the same key is throttled repeatedly within `risk-window-seconds`

Example tuning:
```yaml
rate-limit:
  endpoints:
    - path: /users/login
      on-limit-action: BLOCK_AND_ALERT
      risk-score: 30
      risk-medium-threshold: 50
      risk-high-threshold: 80
      risk-window-seconds: 3600
```

## On-limit Actions (Detailed)
- `BLOCK`: over-limit requests are blocked (429) and counted as incidents.
- `CHALLENGE`: over-limit requests return a challenge response (403) and are counted as incidents.
- `ALERT`: over-limit requests are allowed, an alert is emitted, and incidents are tracked.
- `BLOCK_AND_ALERT`: over-limit requests are blocked (429) and an alert is emitted; incidents are tracked.
- `ALERT_ONLY`: over-limit requests are allowed, an alert is emitted, and incident tracking is skipped (risk stays closer to the base `risk-score`).
Alerting notes:
- With `BLOCK_AND_ALERT` and `alert-once-per-block: true`, an alert is emitted only once per block window per key.
- Set `alert-cooldown-seconds` to avoid email storms when users keep retrying.

Provide your own evaluator:
```java
@Bean
public RiskEvaluator riskEvaluator() {
    return (rule, ctx, decision, incidentCount) -> {
        if (incidentCount >= 5) return RiskLevel.HIGH;
        if (incidentCount >= 2) return RiskLevel.MEDIUM;
        return RiskLevel.LOW;
    };
}
```

## Publishing
Releases are published by pushing a tag like `v1.0.0`.
The GitHub Actions workflow publishes to Maven Central (Central Portal).

Required GitHub secrets:
- `MAVEN_CENTRAL_USERNAME`
- `MAVEN_CENTRAL_PASSWORD`
- `MAVEN_SIGNING_KEY` (ASCII-armored PGP private key)
- `MAVEN_SIGNING_PASSWORD`

Local publish:
```bash
./gradlew publishToMavenLocal -PreleaseVersion=1.0.0
```

Manual Central publish:
```bash
./gradlew publishToMavenCentral -PreleaseVersion=1.0.0
```

## License
Apache-2.0
