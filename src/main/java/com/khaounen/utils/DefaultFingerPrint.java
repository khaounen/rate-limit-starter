package com.khaounen.utils;

import com.khaounen.config.RequestContext;
import com.khaounen.security.ratelimit.FingerprintStrategy;
import jakarta.servlet.http.HttpServletRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.regex.Pattern;

public class DefaultFingerPrint implements FingerprintStrategy {

    private static final Pattern IPV4_PREFIX = Pattern.compile("^(\\d+\\.\\d+\\.\\d+)\\.\\d+$");

    @Override
    public String generate(HttpServletRequest request) {
        String ip = normalizeIp(RequestContext.getIp());
        String ua = normalizeUa(RequestContext.getUserAgent());

        String raw = String.join("|", ip, ua);

        return sha256(raw);
    }

    private static String normalizeIp(String ip) {
        if (ip == null) return "0";

        if (ip.contains(".")) { // IPv4
            var m = IPV4_PREFIX.matcher(ip);
            if (m.matches()) return m.group(1) + ".0";
            return ip;
        }

        if (ip.contains(":")) { // IPv6
            return ip.split(":")[0] + "::";
        }

        return ip;
    }

    private static String normalizeUa(String ua) {
        if (ua == null) return "ua-null";
        return ua.toLowerCase()
                .replaceAll("\\d+(\\.\\d+)*", "")
                .replaceAll("\\s+", " ");
    }

    private static String sha256(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Fingerprint error", e);
        }
    }
}
