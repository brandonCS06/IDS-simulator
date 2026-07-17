package com.ids;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class IcmpSweepRule implements RuleEngineRules {
    private static final long WINDOW_MS = 60_000;
    private static final int ICMP_THRESHOLD = 30;
    private static final int ICMP_ECHO_REQUEST_TYPE = 8;

    private final Map<String, List<Event>> recentEventsByIp = new HashMap<String, List<Event>>();
    private final String ruleName = "IcmpSweepRule";
    private final String severity = "high";

    @Override
    public List<Alert> onEvent(Event event) {
        if (event == null || !isIcmpEvent(event)) {
            return Collections.emptyList();
        }

        Integer icmpType = getMetadataIcmpType(event);
        if (icmpType != null && icmpType.intValue() != ICMP_ECHO_REQUEST_TYPE) {
            return Collections.emptyList();
        }

        String destinationIp = getMetadataString(event, "destination_ip");
        if (destinationIp == null || destinationIp.trim().isEmpty()) {
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

        Set<String> uniqueDestinationIps = new HashSet<String>();
        for (Event historyEvent : history) {
            String historyDestinationIp = getMetadataString(historyEvent, "destination_ip");
            if (historyDestinationIp != null && !historyDestinationIp.trim().isEmpty()) {
                uniqueDestinationIps.add(historyDestinationIp);
            }
        }

        if (uniqueDestinationIps.size() >= ICMP_THRESHOLD) {
            Map<String, Object> metrics = new HashMap<String, Object>();
            metrics.put("unique_destination_ips", Integer.valueOf(uniqueDestinationIps.size()));
            metrics.put("threshold", Integer.valueOf(ICMP_THRESHOLD));
            metrics.put("window_ms", Long.valueOf(WINDOW_MS));
            metrics.put("window_seconds", Long.valueOf(WINDOW_MS / 1000));
            metrics.put("icmp_type", Integer.valueOf(ICMP_ECHO_REQUEST_TYPE));

            String description = "Source " + sourceIp + " sent ICMP echo requests to "
                + uniqueDestinationIps.size() + " unique destination IPs within "
                + (WINDOW_MS / 1000) + " seconds, which suggests network sweep reconnaissance.";
            String recommendation = "Confirm whether this is expected monitoring or discovery traffic; unexpected sweeps should be investigated as reconnaissance.";

            Alert alert = new Alert(
                event.getTimestamp(),
                ruleName,
                severity,
                new ArrayList<Event>(history),
                sourceIp,
                description,
                recommendation,
                metrics
            );
            return Collections.singletonList(alert);
        }

        return Collections.emptyList();
    }

    private boolean isIcmpEvent(Event event) {
        String protocol = getMetadataString(event, "protocol");
        if (protocol != null && "ICMP".equalsIgnoreCase(protocol)) {
            return true;
        }

        Integer icmpType = getMetadataIcmpType(event);
        if (icmpType != null) {
            return true;
        }

        String action = event.getAction();
        return action != null && "ICMP_ECHO_REQUEST".equalsIgnoreCase(action);
    }

    private Integer getMetadataIcmpType(Event event) {
        if (event.getMetadata() == null) {
            return null;
        }

        Object value = event.getMetadata().get("icmp_type");
        if (value == null) {
            value = event.getMetadata().get("icmpType");
        }
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

    private String getMetadataString(Event event, String key) {
        if (event.getMetadata() == null) {
            return null;
        }

        Object value = event.getMetadata().get(key);
        return value == null ? null : value.toString();
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
