package com.ids;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BruteForceRule implements RuleEngineRules {
    private static final long time_Window_ms = 60_000; // 1 minute window
    private static final int threshold = 5; // Threshold for failed logins

    private final SlidingWindow window;
    private final String ruleName = "BruteForceRule";
    private final String severity = "high";

    public BruteForceRule() {
        this.window = new SlidingWindow(time_Window_ms);
    }

    @Override
    public List<Alert> onEvent(Event event) {
        if (event == null) {
            throw new NullPointerException("event must not be null");
        }

        if (!isFailedLogin(event)) {
            return new ArrayList<>();
        }

        window.addEvent(event);

        String sourceIp = event.getSource_ip();
        List<Event> evidence = window.getEvents(sourceIp, null);
        List<Event> failedLogins = new ArrayList<>();
        for (Event evidenceEvent : evidence) {
            if (isFailedLogin(evidenceEvent)) {
                failedLogins.add(evidenceEvent);
            }
        }

        if (failedLogins.size() >= threshold) {
            Map<String, Object> metrics = new HashMap<String, Object>();
            metrics.put("failed_login_count", Integer.valueOf(failedLogins.size()));
            metrics.put("threshold", Integer.valueOf(threshold));
            metrics.put("window_ms", Long.valueOf(time_Window_ms));
            metrics.put("window_seconds", Long.valueOf(time_Window_ms / 1000));

            String description = "Source " + sourceIp + " produced " + failedLogins.size()
                + " failed login attempts within " + (time_Window_ms / 1000)
                + " seconds, meeting the brute-force threshold of " + threshold + ".";
            String recommendation = "Review authentication logs for the source IP, verify whether the user activity is legitimate, and consider rate limiting or temporary blocking.";

            Alert alert = new Alert(
                event.getTimestamp(),
                ruleName,
                severity,
                failedLogins,
                sourceIp,
                description,
                recommendation,
                metrics
            );
            return Collections.singletonList(alert);
        }

        return new ArrayList<>();
    }

    private boolean isFailedLogin(Event event) {
        String action = event.getAction();
        return action != null && ("LOGIN_FAIL".equalsIgnoreCase(action) || "LOGIN_FAILURE".equalsIgnoreCase(action));
    }

    @Override
    public String getName() {
        return ruleName;
    }
}
