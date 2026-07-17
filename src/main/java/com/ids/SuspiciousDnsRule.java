package com.ids;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SuspiciousDnsRule implements RuleEngineRules {
    private static final long DEFAULT_WINDOW_MS = 60_000;
    private static final int DEFAULT_MIN_DNS_EVENTS = 5;
    private static final int DEFAULT_SCORE_THRESHOLD = 8;

    private final Map<String, List<Event>> recentEventsByIp = new HashMap<String, List<Event>>();
    private final long windowMs;
    private final int minimumDnsEvents;
    private final int scoreThreshold;
    private final String ruleName = "SuspiciousDnsRule";
    private final String severity = "high";

    public SuspiciousDnsRule() {
        this(DEFAULT_WINDOW_MS, DEFAULT_MIN_DNS_EVENTS, DEFAULT_SCORE_THRESHOLD);
    }

    public SuspiciousDnsRule(long windowMs, int minimumDnsEvents, int scoreThreshold) {
        if (windowMs <= 0) {
            throw new IllegalArgumentException("windowMs must be positive");
        }
        if (minimumDnsEvents <= 0) {
            throw new IllegalArgumentException("minimumDnsEvents must be positive");
        }
        if (scoreThreshold <= 0) {
            throw new IllegalArgumentException("scoreThreshold must be positive");
        }
        this.windowMs = windowMs;
        this.minimumDnsEvents = minimumDnsEvents;
        this.scoreThreshold = scoreThreshold;
    }

    @Override
    public List<Alert> onEvent(Event event) {
        if (event == null || !isDnsEvent(event)) {
            return Collections.emptyList();
        }

        String sourceIp = event.getSource_ip();
        List<Event> history = recentEventsByIp.get(sourceIp);
        if (history == null) {
            history = new ArrayList<Event>();
            recentEventsByIp.put(sourceIp, history);
        }

        history.add(event);
        pruneExpired(history, event.getTimestamp());

        int totalScore = 0;
        Set<String> indicators = new HashSet<String>();
        for (Event historyEvent : history) {
            totalScore += scoreEvent(historyEvent, indicators);
        }

        if (history.size() >= minimumDnsEvents && totalScore >= scoreThreshold && indicators.size() >= 2) {
            Map<String, Object> metrics = new HashMap<String, Object>();
            metrics.put("dns_event_count", Integer.valueOf(history.size()));
            metrics.put("score", Integer.valueOf(totalScore));
            metrics.put("score_threshold", Integer.valueOf(scoreThreshold));
            metrics.put("minimum_dns_events", Integer.valueOf(minimumDnsEvents));
            metrics.put("window_ms", Long.valueOf(windowMs));
            metrics.put("window_seconds", Long.valueOf(windowMs / 1000));
            metrics.put("indicators", new ArrayList<String>(indicators));

            String description = "Source " + sourceIp + " generated " + history.size()
                + " suspicious DNS events with score " + totalScore + " in "
                + (windowMs / 1000) + " seconds. Indicators include "
                + new ArrayList<String>(indicators) + ".";
            String recommendation = "Inspect DNS query names and response codes for tunneling or exfiltration patterns, especially repeated TXT/NULL/ANY queries and high-entropy labels.";

            return Collections.singletonList(
                new Alert(
                    event.getTimestamp(),
                    ruleName,
                    severity,
                    new ArrayList<Event>(history),
                    sourceIp,
                    description,
                    recommendation,
                    metrics
                )
            );
        }

        return Collections.emptyList();
    }

    private boolean isDnsEvent(Event event) {
        String protocol = event.getProtocol();
        if (protocol != null && "DNS".equalsIgnoreCase(protocol)) {
            return true;
        }

        String queryName = getMetadataString(event, "query_name");
        String qtype = getMetadataString(event, "qtype");
        String rcode = getMetadataString(event, "rcode");
        return queryName != null || qtype != null || rcode != null;
    }

    private int scoreEvent(Event event, Set<String> indicators) {
        int score = 0;

        String queryName = getMetadataString(event, "query_name");
        Integer labelLength = getMetadataInteger(event, "label_length");
        Double entropy = getMetadataDouble(event, "entropy");
        String qtype = getMetadataString(event, "qtype");
        String rcode = getMetadataString(event, "rcode");
        Integer responseSize = getMetadataInteger(event, "response_size");

        if (queryName != null) {
            int longestLabel = getLongestLabelLength(queryName);
            if (longestLabel >= 24 || (labelLength != null && labelLength.intValue() >= 24)) {
                score += 2;
                indicators.add("long_query_name");
            }
        }

        if (entropy != null && entropy.doubleValue() >= 4.0d) {
            score += 2;
            indicators.add("high_entropy");
        }

        if (qtype != null && ("TXT".equalsIgnoreCase(qtype) || "NULL".equalsIgnoreCase(qtype) || "ANY".equalsIgnoreCase(qtype))) {
            score += 2;
            indicators.add("suspicious_qtype");
        }

        if (rcode != null && ("NXDOMAIN".equalsIgnoreCase(rcode) || "SERVFAIL".equalsIgnoreCase(rcode) || "REFUSED".equalsIgnoreCase(rcode))) {
            score += 2;
            indicators.add("dns_failure");
        }

        if (responseSize != null && responseSize.intValue() >= 512) {
            score += 1;
            indicators.add("large_response");
        }

        return score;
    }

    private int getLongestLabelLength(String queryName) {
        String[] labels = queryName.split("\\.");
        int longest = 0;
        for (String label : labels) {
            if (label.length() > longest) {
                longest = label.length();
            }
        }
        return longest;
    }

    private String getMetadataString(Event event, String key) {
        if (event.getMetadata() == null) {
            return null;
        }
        Object value = event.getMetadata().get(key);
        return value == null ? null : value.toString();
    }

    private Integer getMetadataInteger(Event event, String key) {
        if (event.getMetadata() == null) {
            return null;
        }

        Object value = event.getMetadata().get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Integer) {
            return (Integer) value;
        }
        if (value instanceof Number) {
            return Integer.valueOf(((Number) value).intValue());
        }
        if (value instanceof String) {
            try {
                return Integer.valueOf((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private Double getMetadataDouble(Event event, String key) {
        if (event.getMetadata() == null) {
            return null;
        }

        Object value = event.getMetadata().get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Double) {
            return (Double) value;
        }
        if (value instanceof Number) {
            return Double.valueOf(((Number) value).doubleValue());
        }
        if (value instanceof String) {
            try {
                return Double.valueOf((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private void pruneExpired(List<Event> history, long timestamp) {
        long cutoff = timestamp - windowMs;
        while (!history.isEmpty() && history.get(0).getTimestamp() < cutoff) {
            history.remove(0);
        }
    }

    @Override
    public String getName() {
        return ruleName;
    }
}
