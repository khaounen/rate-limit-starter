package com.khaounen.ratelimit.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

public class IpUtils {

    private IpUtils() {
    }

    public static String resolveIp(HttpServletRequest request) {
        String[] headers = {
                "X-Forwarded-For",
                "X-Real-IP",
                "CF-Connecting-IP",
                "True-Client-IP"
        };

        for (String header : headers) {
            String value = request.getHeader(header);
            if (StringUtils.hasText(value)) {
                return value.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }
}
