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
        //ignores non login events
        if(event.getAction() == null || !event.getAction().toUpperCase().startsWith("LOGIN")){
            return new ArrayList<>();
        }

        // Add the event to the sliding window
        window.addEvent(event);

        // Check if the count of events for this source IP exceeds the threshold
        String sourceIp = event.getSource_ip();
        if(window.count(sourceIp, "login") >= threshold) {
            //Collect evidence : recent login events from same IP
            List<Event> evidence = window.getEvents(sourceIp,"login");


            Alert alert = new Alert(
                event.getTimestamp(),
                ruleName,
                severity,
                evidence,
                sourceIp
            );

            return List.of(alert);
            
        }

        return new ArrayList<>();
    }

    @Override
    public String getName() {
        return ruleName;
    }
}
