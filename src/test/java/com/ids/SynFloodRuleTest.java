package com.ids;

import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class SynFloodRuleTest {

    private static final long WINDOW_MS = 10_000;
    private static final int SYN_THRESHOLD = 60;

    private SynFloodRule rule;

    @Before
    public void setUp() {
        rule = new SynFloodRule();
    }

    @Test
    public void testRuleCreation() {
        assertNotNull(rule);
        assertEquals("SynFloodRule", rule.getName());
    }

    @Test
    public void testNullEventAndNonTcpIgnored() {
        List<Alert> nullAlerts = rule.onEvent(null);
        assertNotNull(nullAlerts);
        assertTrue(nullAlerts.isEmpty());

        HashMap<String, Object> metadata = new HashMap<String, Object>();
        metadata.put("protocol", "UDP");
        metadata.put("tcp_flags", "SYN");
        Event udpEvent = new Event(1_000, "10.0.0.5", "eve", "PROBE", "api_gateway", metadata);

        List<Alert> udpAlerts = rule.onEvent(udpEvent);
        assertTrue("Non-TCP events should be ignored", udpAlerts.isEmpty());
    }

    @Test
    public void testBelowThresholdNoAlert() {
        for (int i = 0; i < SYN_THRESHOLD - 1; i++) {
            Event event = createSynEvent(1_000 + (i * 100L), "10.0.0.5", "198.51.100.20", 443);
            List<Alert> alerts = rule.onEvent(event);
            assertTrue("Should not alert below SYN threshold", alerts.isEmpty());
        }
    }

    @Test
    public void testThresholdReachedWithLowAckRatioTriggersAlert() {
        List<Alert> alerts = null;

        for (int i = 0; i < SYN_THRESHOLD; i++) {
            Event event = createSynEvent(1_000 + (i * 100L), "10.0.0.5", "198.51.100.20", 443);
            alerts = rule.onEvent(event);
        }

        assertNotNull(alerts);
        assertFalse("Should alert once threshold is reached with sparse ACKs", alerts.isEmpty());
        assertEquals(1, alerts.size());
        assertEquals("SynFloodRule", alerts.get(0).getRule_name());
        assertEquals("high", alerts.get(0).getSeverity());
        assertEquals("10.0.0.5", alerts.get(0).getSource_ip());
    }

    @Test
    public void testHighAckRatioSuppressesAlert() {
        // Interleave ACK events so completion ratio is high at threshold time.
        for (int i = 0; i < SYN_THRESHOLD; i++) {
            Event synEvent = createSynEvent(2_000 + (i * 80L), "10.0.0.5", "198.51.100.20", 443);
            List<Alert> synAlerts = rule.onEvent(synEvent);

            Event ackEvent = createAckEvent(2_001 + (i * 80L), "10.0.0.5", "198.51.100.20", 443);
            List<Alert> ackAlerts = rule.onEvent(ackEvent);

            assertTrue("High ACK completion should suppress SYN flood alert", synAlerts.isEmpty());
            assertTrue("High ACK completion should suppress SYN flood alert", ackAlerts.isEmpty());
        }
    }

    @Test
    public void testWindowExpirationClearsPriorBurst() {
        for (int i = 0; i < SYN_THRESHOLD; i++) {
            Event synEvent = createSynEvent(5_000 + (i * 80L), "10.0.0.5", "198.51.100.20", 443);
            rule.onEvent(synEvent);
        }

        Event farFutureSyn = createSynEvent(5_000 + WINDOW_MS + 2_000, "10.0.0.5", "198.51.100.20", 443);
        List<Alert> alerts = rule.onEvent(farFutureSyn);

        assertTrue("Old window events should expire before evaluating new burst", alerts.isEmpty());
    }

    @Test
    public void testSourceIsolation() {
        for (int i = 0; i < SYN_THRESHOLD - 1; i++) {
            rule.onEvent(createSynEvent(10_000 + (i * 100L), "10.0.0.5", "198.51.100.20", 443));
        }

        List<Alert> alertsOtherSource = rule.onEvent(createSynEvent(10_000, "10.0.0.6", "198.51.100.20", 443));
        assertTrue("Different source IP should maintain separate counters", alertsOtherSource.isEmpty());
    }

    @Test
    public void testDestinationTupleIsolation() {
        // Split SYNs across two destination ports for same source/destination IP, should not combine.
        for (int i = 0; i < 30; i++) {
            List<Alert> alertsA = rule.onEvent(createSynEvent(20_000 + (i * 100L), "10.0.0.5", "198.51.100.20", 443));
            List<Alert> alertsB = rule.onEvent(createSynEvent(20_000 + (i * 100L), "10.0.0.5", "198.51.100.20", 8443));
            assertTrue(alertsA.isEmpty());
            assertTrue(alertsB.isEmpty());
        }
    }

    @Test
    public void testMixedFlagRepresentations() {
        // First 59 SYN events use boolean metadata.
        for (int i = 0; i < SYN_THRESHOLD - 1; i++) {
            Event event = createSynEventWithBooleans(30_000 + (i * 100L), "10.0.0.5", "198.51.100.20", 443);
            List<Alert> alerts = rule.onEvent(event);
            assertTrue(alerts.isEmpty());
        }

        // Last SYN event uses tcp_flags string and should trigger.
        Event finalEvent = createSynEvent(30_000 + ((SYN_THRESHOLD - 1) * 100L), "10.0.0.5", "198.51.100.20", 443);
        List<Alert> alerts = rule.onEvent(finalEvent);

        assertFalse("Rule should support mixed boolean and tcp_flags representations", alerts.isEmpty());
    }

    private Event createSynEvent(long timestamp, String sourceIp, String destinationIp, int destinationPort) {
        HashMap<String, Object> metadata = new HashMap<String, Object>();
        metadata.put("protocol", "TCP");
        metadata.put("destination_ip", destinationIp);
        metadata.put("destination_port", destinationPort);
        metadata.put("tcp_flags", "SYN");
        metadata.put("syn", Boolean.TRUE);
        metadata.put("ack", Boolean.FALSE);
        return new Event(timestamp, sourceIp, "eve", "CONNECTION_ATTEMPT", "web_server", metadata);
    }

    private Event createSynEventWithBooleans(long timestamp, String sourceIp, String destinationIp, int destinationPort) {
        HashMap<String, Object> metadata = new HashMap<String, Object>();
        metadata.put("protocol", "TCP");
        metadata.put("destination_ip", destinationIp);
        metadata.put("destination_port", destinationPort);
        metadata.put("syn", Boolean.TRUE);
        metadata.put("ack", Boolean.FALSE);
        return new Event(timestamp, sourceIp, "eve", "CONNECTION_ATTEMPT", "web_server", metadata);
    }

    private Event createAckEvent(long timestamp, String sourceIp, String destinationIp, int destinationPort) {
        HashMap<String, Object> metadata = new HashMap<String, Object>();
        metadata.put("protocol", "TCP");
        metadata.put("destination_ip", destinationIp);
        metadata.put("destination_port", destinationPort);
        metadata.put("tcp_flags", "ACK");
        metadata.put("syn", Boolean.FALSE);
        metadata.put("ack", Boolean.TRUE);
        return new Event(timestamp, sourceIp, "eve", "CONNECTION_ACK", "web_server", metadata);
    }
}
