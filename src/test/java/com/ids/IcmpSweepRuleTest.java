package com.ids;

import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class IcmpSweepRuleTest {

    private IcmpSweepRule rule;
    private static final int ICMP_SWEEP_THRESHOLD = 30;
    private static final long WINDOW_MS = 60_000;

    @Before
    public void setUp() {
        rule = new IcmpSweepRule();
    }

    @Test
    public void testRuleCreation() {
        assertNotNull(rule);
        assertEquals("IcmpSweepRule", rule.getName());
    }

    @Test
    public void testNullEvent() {
        List<Alert> alerts = rule.onEvent(null);
        assertNotNull(alerts);
        assertTrue(alerts.isEmpty());
    }

    @Test
    public void testNonIcmpEventIgnored() {
        Event event = new Event(1000L, "10.0.0.5", "alice", "LOGIN_SUCCESS", "web_server", new HashMap<String, Object>());
        List<Alert> alerts = rule.onEvent(event);

        assertNotNull(alerts);
        assertTrue(alerts.isEmpty());
    }

    @Test
    public void testIcmpTypeMismatchIgnored() {
        HashMap<String, Object> metadata = new HashMap<String, Object>();
        metadata.put("protocol", "ICMP");
        metadata.put("icmp_type", 3);
        metadata.put("destination_ip", "198.51.100.10");

        Event event = new Event(1000L, "10.0.0.5", "alice", "ICMP_ECHO_REQUEST", "icmp_probe", metadata);
        List<Alert> alerts = rule.onEvent(event);

        assertNotNull(alerts);
        assertTrue(alerts.isEmpty());
    }

    @Test
    public void testBelowThresholdNoAlert() {
        for (int i = 0; i < ICMP_SWEEP_THRESHOLD - 1; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("protocol", "ICMP");
            metadata.put("icmp_type", 8);
            metadata.put("destination_ip", "198.51.100." + (i + 1));

            Event event = new Event(1000L + (i * 200L), "10.0.0.5", "alice", "ICMP_ECHO_REQUEST", "icmp_probe", metadata);
            List<Alert> alerts = rule.onEvent(event);

            assertTrue("Alert should not trigger below threshold", alerts.isEmpty());
        }
    }

    @Test
    public void testIcmpSweepDetection() {
        for (int i = 0; i < ICMP_SWEEP_THRESHOLD; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("protocol", "ICMP");
            metadata.put("icmp_type", 8);
            metadata.put("destination_ip", "198.51.100." + (i + 1));

            Event event = new Event(1000L + (i * 200L), "10.0.0.5", "alice", "ICMP_ECHO_REQUEST", "icmp_probe", metadata);
            List<Alert> alerts = rule.onEvent(event);

            if (i < ICMP_SWEEP_THRESHOLD - 1) {
                assertTrue("Alert should not trigger until threshold", alerts.isEmpty());
            } else {
                assertFalse("Alert should trigger at threshold", alerts.isEmpty());
                assertEquals(1, alerts.size());
                Alert alert = alerts.get(0);
                assertEquals("IcmpSweepRule", alert.getRule_name());
                assertEquals("high", alert.getSeverity());
                assertEquals("10.0.0.5", alert.getSource_ip());
                assertNotNull(alert.getEvidence());
                assertTrue(alert.getEvidence().size() >= ICMP_SWEEP_THRESHOLD);
            }
        }
    }

    @Test
    public void testRepeatedDestinationDoesNotCountTwice() {
        for (int i = 0; i < ICMP_SWEEP_THRESHOLD; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("protocol", "ICMP");
            metadata.put("icmp_type", 8);
            metadata.put("destination_ip", "198.51.100." + ((i % 10) + 1));

            Event event = new Event(1000L + (i * 200L), "10.0.0.5", "alice", "ICMP_ECHO_REQUEST", "icmp_probe", metadata);
            List<Alert> alerts = rule.onEvent(event);

            assertTrue("Duplicate destinations should not trigger an alert", alerts.isEmpty());
        }
    }

    @Test
    public void testMultipleSourceIPs() {
        for (int i = 0; i < ICMP_SWEEP_THRESHOLD - 1; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("protocol", "ICMP");
            metadata.put("icmp_type", 8);
            metadata.put("destination_ip", "198.51.100." + (i + 1));

            Event event = new Event(1000L + (i * 200L), "10.0.0.5", "alice", "ICMP_ECHO_REQUEST", "icmp_probe", metadata);
            rule.onEvent(event);
        }

        for (int i = 0; i < ICMP_SWEEP_THRESHOLD - 1; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("protocol", "ICMP");
            metadata.put("icmp_type", 8);
            metadata.put("destination_ip", "198.51.100." + (i + 1));

            Event event = new Event(2000L + (i * 200L), "10.0.0.6", "bob", "ICMP_ECHO_REQUEST", "icmp_probe", metadata);
            List<Alert> alerts = rule.onEvent(event);

            assertTrue("Second source should stay below threshold", alerts.isEmpty());
        }
    }

    @Test
    public void testWindowExpiration() {
        for (int i = 0; i < ICMP_SWEEP_THRESHOLD; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("protocol", "ICMP");
            metadata.put("icmp_type", 8);
            metadata.put("destination_ip", "198.51.100." + (i + 1));

            Event event = new Event(1000L + (i * 200L), "10.0.0.5", "alice", "ICMP_ECHO_REQUEST", "icmp_probe", metadata);
            rule.onEvent(event);
        }

        HashMap<String, Object> metadata = new HashMap<String, Object>();
        metadata.put("protocol", "ICMP");
        metadata.put("icmp_type", 8);
        metadata.put("destination_ip", "198.51.100.200");

        Event expiredEvent = new Event(1000L + WINDOW_MS + 1000L, "10.0.0.5", "alice", "ICMP_ECHO_REQUEST", "icmp_probe", metadata);
        List<Alert> alerts = rule.onEvent(expiredEvent);

        assertTrue("Expired events should be removed from the window", alerts.isEmpty());
    }

    @Test
    public void testStringIcmpTypeValue() {
        HashMap<String, Object> metadata = new HashMap<String, Object>();
        metadata.put("protocol", "ICMP");
        metadata.put("icmp_type", "8");
        metadata.put("destination_ip", "198.51.100.10");

        Event event = new Event(1000L, "10.0.0.5", "alice", "ICMP_ECHO_REQUEST", "icmp_probe", metadata);
        List<Alert> alerts = rule.onEvent(event);

        assertNotNull(alerts);
        assertTrue(alerts.isEmpty());
    }
}