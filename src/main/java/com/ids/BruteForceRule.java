package com.ids;

import java.util.List;
import java.util.ArrayList;

public class BruteForceRule implements RuleEngineRules{
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
        if (window.count(sourceIp, "LOGIN_FAIL") >= threshold) {
            List<Event> evidence = window.getEvents(sourceIp, "LOGIN_FAIL");

            Alert alert = new Alert(
                event.getTimestamp(),
                ruleName,
                severity,
                evidence,
                sourceIp
            );

            return java.util.Collections.singletonList(alert);
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
