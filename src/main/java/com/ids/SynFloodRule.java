package com.ids;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SynFloodRule implements RuleEngineRules {
    private static final long WINDOW_MS = 10_000;
    private static final int SYN_THRESHOLD = 60;
    private static final int MIN_SYN_FOR_RATIO = 30;
    private static final double MAX_ACK_RATIO = 0.20d;

    private final Map<String, List<Event>> recentEventsByTuple = new HashMap<String, List<Event>>();
    private final String ruleName = "SynFloodRule";
    private final String severity = "high";

    @Override
    public List<Alert> onEvent(Event event) {
        if (event == null || !isTcpEvent(event)) {
            return Collections.emptyList();
        }

        FlagState flags = readFlagState(event);
        if (!flags.isSyn() && !flags.isAck()) {
            return Collections.emptyList();
        }

        String tupleKey = buildTupleKey(event);
        List<Event> history = recentEventsByTuple.get(tupleKey);
        if (history == null) {
            history = new ArrayList<Event>();
            recentEventsByTuple.put(tupleKey, history);
        }

        history.add(event);
        pruneExpired(history, event.getTimestamp());

        int synCount = 0;
        int ackCount = 0;

        for (Event historyEvent : history) {
            FlagState historyFlags = readFlagState(historyEvent);
            if (historyFlags.isSyn()) {
                synCount++;
            }
            if (historyFlags.isAck()) {
                ackCount++;
            }
        }

        if (synCount >= SYN_THRESHOLD && synCount >= MIN_SYN_FOR_RATIO) {
            double ackRatio = (double) ackCount / (double) Math.max(1, synCount);
            if (ackRatio < MAX_ACK_RATIO) {
                String destinationIp = normalizeKeyPart(getMetadataString(event, "destination_ip"));
                Integer destinationPort = event.getDestinationPort();

                Map<String, Object> metrics = new HashMap<String, Object>();
                metrics.put("syn_count", Integer.valueOf(synCount));
                metrics.put("ack_count", Integer.valueOf(ackCount));
                metrics.put("ack_ratio", Double.valueOf(ackRatio));
                metrics.put("max_ack_ratio", Double.valueOf(MAX_ACK_RATIO));
                metrics.put("syn_threshold", Integer.valueOf(SYN_THRESHOLD));
                metrics.put("window_ms", Long.valueOf(WINDOW_MS));
                metrics.put("window_seconds", Long.valueOf(WINDOW_MS / 1000));
                metrics.put("destination_ip", destinationIp);
                metrics.put("destination_port", destinationPort == null ? "*" : destinationPort);

                String description = "Source " + event.getSource_ip() + " sent " + synCount
                    + " TCP SYN packets toward " + destinationIp + ":"
                    + (destinationPort == null ? "*" : destinationPort.toString())
                    + " in " + (WINDOW_MS / 1000) + " seconds, but only " + ackCount
                    + " ACK packets were observed. The ACK ratio was " + ackRatio
                    + ", below the allowed " + MAX_ACK_RATIO + ".";
                String recommendation = "Review TCP handshake completion for this flow; many SYNs with few ACKs can indicate half-open connection flooding.";

                return Collections.singletonList(
                    new Alert(
                        event.getTimestamp(),
                        ruleName,
                        severity,
                        new ArrayList<Event>(history),
                        event.getSource_ip(),
                        description,
                        recommendation,
                        metrics
                    )
                );
            }
        }

        return Collections.emptyList();
    }

    private boolean isTcpEvent(Event event) {
        String protocol = event.getProtocol();
        return protocol != null && "TCP".equalsIgnoreCase(protocol);
    }

    private String buildTupleKey(Event event) {
        String sourceIp = normalizeKeyPart(event.getSource_ip());
        String destinationIp = normalizeKeyPart(getMetadataString(event, "destination_ip"));
        Integer destinationPort = event.getDestinationPort();
        String destinationPortPart = destinationPort == null ? "*" : String.valueOf(destinationPort.intValue());

        return sourceIp + "|" + destinationIp + "|" + destinationPortPart;
    }

    private String normalizeKeyPart(String value) {
        if (value == null || value.trim().isEmpty()) {
            return "*";
        }
        return value.trim();
    }

    private FlagState readFlagState(Event event) {
        String tcpFlags = getMetadataString(event, "tcp_flags");

        Boolean synBoolean = getMetadataBoolean(event, "syn");
        Boolean ackBoolean = getMetadataBoolean(event, "ack");

        boolean syn = hasFlag(tcpFlags, "SYN");
        boolean ack = hasFlag(tcpFlags, "ACK");

        if (synBoolean != null) {
            syn = synBoolean.booleanValue();
        }
        if (ackBoolean != null) {
            ack = ackBoolean.booleanValue();
        }

        return new FlagState(syn, ack);
    }

    private boolean hasFlag(String flagsValue, String flag) {
        if (flagsValue == null) {
            return false;
        }

        String normalized = flagsValue.toUpperCase();
        if (normalized.equals(flag)) {
            return true;
        }

        String[] tokens = normalized.split("[^A-Z0-9]+");
        for (String token : tokens) {
            if (flag.equals(token)) {
                return true;
            }
        }

        // Covers compact forms such as SYNACK when delimiters are omitted.
        if ("SYN".equals(flag) && normalized.contains("SYN")) {
            return true;
        }
        if ("ACK".equals(flag) && normalized.contains("ACK")) {
            return true;
        }

        return false;
    }

    private String getMetadataString(Event event, String key) {
        if (event.getMetadata() == null) {
            return null;
        }

        Object value = event.getMetadata().get(key);
        return value == null ? null : value.toString();
    }

    private Boolean getMetadataBoolean(Event event, String key) {
        if (event.getMetadata() == null) {
            return null;
        }

        Object value = event.getMetadata().get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof Number) {
            return ((Number) value).intValue() != 0;
        }
        if (value instanceof String) {
            String normalized = ((String) value).trim().toLowerCase();
            if ("true".equals(normalized) || "1".equals(normalized) || "yes".equals(normalized)) {
                return Boolean.TRUE;
            }
            if ("false".equals(normalized) || "0".equals(normalized) || "no".equals(normalized)) {
                return Boolean.FALSE;
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

    private static final class FlagState {
        private final boolean syn;
        private final boolean ack;

        private FlagState(boolean syn, boolean ack) {
            this.syn = syn;
            this.ack = ack;
        }

        private boolean isSyn() {
            return syn;
        }

        private boolean isAck() {
            return ack;
        }
    }
}
