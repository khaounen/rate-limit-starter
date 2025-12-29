package com.khaounen.ratelimit.config;

public final class RequestContext {

    private static final ThreadLocal<String> IP_ADDRESS = new ThreadLocal<>();
    private static final ThreadLocal<String> USER_AGENT = new ThreadLocal<>();
    private static final ThreadLocal<String> FINGERPRINT = new ThreadLocal<>();

    private RequestContext() {}

    public static void setIp(String ipAddress) {
        IP_ADDRESS.set(ipAddress);
    }

    public static String getIp() {
        return IP_ADDRESS.get();
    }

    public static void setUserAgent(String userAgent) {
        USER_AGENT.set(userAgent);
    }

    public static String getUserAgent() {
        return USER_AGENT.get();
    }

    public static void setFingerprint(String fingerprint) {
        FINGERPRINT.set(fingerprint);
    }

    public static String getFingerprint() {
        return FINGERPRINT.get();
    }

    public static void clear() {
        IP_ADDRESS.remove();
        USER_AGENT.remove();
        FINGERPRINT.remove();
    }
}
