# rate-limit-starter

Spring Boot rate-limit starter with fingerprint-based throttling, Redis TTL counters, and per-endpoint rules.

## Features
- Per-endpoint rate limits with Ant-style path patterns.
- Fingerprint strategy interface (default implementation included).
- Redis-backed counters with Caffeine in-memory fallback.
- Request context filter to capture IP and user-agent.

## Installation
```gradle
dependencies {
    implementation "com.khaounen:rate-limit-starter:1.0.0"
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
      identifier-params:
        - username
```

## Filter Order
The starter registers two filters in the Spring Security chain:
- `RequestContextFilter`: runs early (before auth) to capture IP and User-Agent.
- `RateLimitFilter`: runs after auth so it can apply `authenticated-multiplier`.

This ordering ensures the fingerprint is always available, and authenticated users can benefit from higher limits.

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
- `apply-authenticated-multiplier` (boolean): disable multiplier for sensitive endpoints (OTP/signup).
- `identifier-params` (list): request params or JSON fields used as secondary key (email/phone/username).
- `identifier-header` (string): header used as secondary key.
- `key` (string): custom Redis key prefix for the rule.
- `key-suffix` (string): suffix appended to the key (useful for grouping).

Notes:
- Counters use `rate:count:*` with TTL = `window-seconds`.
- Blocks use `rate:block:*` with TTL = `block-seconds`.
- Redis is used when a RedisTemplate bean is present; otherwise Caffeine in-memory caches are used.
- Caffeine entries expire per entry (window or block duration), preventing unbounded growth in local mode.

## Custom Fingerprint
Provide your own strategy:

```java
@Bean
public FingerprintStrategy fingerprintStrategy() {
    return request -> "custom-fingerprint";
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
