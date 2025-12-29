# rate-limit-starter

Spring Boot rate-limit starter with fingerprint-based throttling, Redis TTL counters, and per-endpoint rules.

## Features
- Per-endpoint rate limits with Ant-style path patterns.
- Fingerprint strategy interface (default implementation included).
- Redis-backed counters with local fallback.
- Optional fail-closed mode with grace limits.
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
      fail-closed: true
      identifier-params:
        - username
```

## Custom Fingerprint
Provide your own strategy:

```java
@Bean
public FingerprintStrategy fingerprintStrategy() {
    return request -> "custom-fingerprint";
}
```

## Publishing
This project uses `maven-publish` + `signing` for OSSRH.

## License
Apache-2.0
