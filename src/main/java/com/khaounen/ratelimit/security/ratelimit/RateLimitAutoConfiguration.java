package com.khaounen.ratelimit.security.ratelimit;

import com.khaounen.ratelimit.config.RequestContextFilter;
import com.khaounen.ratelimit.security.filters.RateLimitFilter;
import com.khaounen.ratelimit.utils.DefaultFingerPrint;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@Slf4j
@AutoConfiguration
@EnableConfigurationProperties(RateLimitProperties.class)
public class RateLimitAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public FingerprintStrategy fingerprintStrategy() {
        return new DefaultFingerPrint();
    }

    @Bean(name = "rateLimitRequestContextFilter")
    @ConditionalOnMissingBean
    public RequestContextFilter requestContextFilter(FingerprintStrategy fingerprintStrategy) {
        return new RequestContextFilter(fingerprintStrategy);
    }

    @Bean
    @ConditionalOnMissingBean
    public RateLimitService rateLimitService(
            org.springframework.beans.factory.ObjectProvider<org.springframework.data.redis.core.RedisTemplate<String, Long>> redisTemplateProvider,
            FingerprintStrategy fingerprintStrategy
    ) {
        return new RateLimitService(redisTemplateProvider, fingerprintStrategy);
    }

    @Bean
    @ConditionalOnMissingBean
    public RateLimitFilter rateLimitFilter(
            RateLimitProperties properties,
            RateLimitService service,
            org.springframework.beans.factory.ObjectProvider<ObjectMapper> objectMapperProvider
    ) {
        ObjectMapper objectMapper = objectMapperProvider.getIfAvailable(ObjectMapper::new);
        return new RateLimitFilter(properties, service, objectMapper);
    }
}
