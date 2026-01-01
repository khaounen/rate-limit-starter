package com.khaounen.security.ratelimit;

import com.khaounen.config.RequestContextFilter;
import com.khaounen.security.filters.RateLimitFilter;
import com.khaounen.utils.DefaultFingerPrint;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.mail.javamail.JavaMailSender;

@Slf4j
@AutoConfiguration
@EnableConfigurationProperties({RateLimitProperties.class, RateLimitAlertProperties.class})
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
            FingerprintStrategy fingerprintStrategy,
            RateLimitAlertListener alertListener,
            RiskEvaluator riskEvaluator
    ) {
        return new RateLimitService(redisTemplateProvider, fingerprintStrategy, alertListener, riskEvaluator);
    }

    @Bean
    @ConditionalOnMissingBean
    public RateLimitFilter rateLimitFilter(
            RateLimitProperties properties,
            RateLimitService service,
            org.springframework.beans.factory.ObjectProvider<ObjectMapper> objectMapperProvider,
            RateLimitChallengeHandler challengeHandler,
            ObjectProvider<UserVerificationResolver> userVerificationResolverProvider,
            ObjectProvider<DeviceAttestationResolver> deviceAttestationResolverProvider
    ) {
        ObjectMapper objectMapper = objectMapperProvider.getIfAvailable(ObjectMapper::new);
        UserVerificationResolver userVerificationResolver = userVerificationResolverProvider.getIfAvailable();
        DeviceAttestationResolver deviceAttestationResolver = deviceAttestationResolverProvider.getIfAvailable();
        return new RateLimitFilter(
                properties,
                service,
                objectMapper,
                challengeHandler,
                userVerificationResolver,
                deviceAttestationResolver
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public RateLimitAlertListener rateLimitAlertListener(
            RateLimitAlertProperties properties,
            ObjectProvider<ObjectMapper> objectMapperProvider,
            ObjectProvider<JavaMailSender> mailSenderProvider
    ) {
        return new RateLimitAlertDispatcher(properties, objectMapperProvider, mailSenderProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public RateLimitChallengeHandler rateLimitChallengeHandler() {
        return new DefaultRateLimitChallengeHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskEvaluator riskEvaluator() {
        return new DefaultRiskEvaluator();
    }
}
