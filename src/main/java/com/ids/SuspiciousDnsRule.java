package com.ids;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SuspiciousDnsRule implements RuleEngineRules {
    private static final long WINDOW_MS = 60_000;
    private static final int MIN_DNS_EVENTS = 5;
    private static final int SCORE_THRESHOLD = 8;

    private final Map<String, List<Event>> recentEventsByIp = new HashMap<String, List<Event>>();
    private final String ruleName = "SuspiciousDnsRule";
    private final String severity = "high";

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

        if (history.size() >= MIN_DNS_EVENTS && totalScore >= SCORE_THRESHOLD && indicators.size() >= 2) {
            return Collections.singletonList(
                new Alert(
                    event.getTimestamp(),
                    ruleName,
                    severity,
                    new ArrayList<Event>(history),
                    sourceIp
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
        long cutoff = timestamp - WINDOW_MS;
        while (!history.isEmpty() && history.get(0).getTimestamp() < cutoff) {
            history.remove(0);
        }
    }

    @Override
    public String getName() {
        return ruleName;
    }
}