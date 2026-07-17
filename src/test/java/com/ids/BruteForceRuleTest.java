package com.ids;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import java.util.HashMap;
import java.util.List;

public class BruteForceRuleTest {

    private BruteForceRule rule;
    private static final int THRESHOLD = 5; // Must match the rule's threshold
    private static final long WINDOW_MS = 60_000;

    @Before
    public void setUp() {
        rule = new BruteForceRule();
    }

    @Test
    public void testRuleCreation() {
        assertNotNull(rule);
        assertEquals("BruteForceRule", rule.getName());
    }

    @Test
    public void testNonLoginEventIgnored() {
        Event event = new Event(1000, "192.168.1.1", "alice", "ACCESS_GRANTED", "web", new HashMap<>());
        List<Alert> alerts = rule.onEvent(event);
        
        assertNotNull(alerts);
        assertTrue(alerts.isEmpty());
    }

    @Test(expected = NullPointerException.class)
    public void testNullEvent() {
        rule.onEvent(null);
    }

    @Test
    public void testBelowThresholdNoAlert() {
        // Add 4 failed login events (below threshold of 5)
        for (int i = 0; i < 4; i++) {
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>());
            List<Alert> alerts = rule.onEvent(event);
            assertTrue("Alert should not be triggered below threshold", alerts.isEmpty());
        }
    }

    @Test
    public void testThresholdTriggersAlert() {
        // Add events to trigger alert
        for (int i = 0; i < THRESHOLD; i++) {
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>());
            List<Alert> alerts = rule.onEvent(event);
            
            if (i < THRESHOLD - 1) {
                assertTrue("Alert should not be triggered until threshold", alerts.isEmpty());
            } else {
                assertFalse("Alert should be triggered at threshold", alerts.isEmpty());
                assertEquals(1, alerts.size());
                Alert alert = alerts.get(0);
                assertEquals("BruteForceRule", alert.getRule_name());
                assertEquals("high", alert.getSeverity());
                assertEquals("192.168.1.1", alert.getSource_ip());
                assertNotNull(alert.getDescription());
                assertTrue(alert.getDescription().contains("failed login attempts"));
                assertNotNull(alert.getRecommendation());
                assertNotNull(alert.getMetrics());
                assertEquals(Integer.valueOf(THRESHOLD), alert.getMetrics().get("failed_login_count"));
                assertEquals(Integer.valueOf(THRESHOLD), alert.getMetrics().get("threshold"));
            }
        }
    }

    @Test
    public void testMultipleSourceIPs() {
        // Add 5 failed logins from IP 1
        for (int i = 0; i < THRESHOLD; i++) {
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>());
            rule.onEvent(event);
        }
        
        // Add 4 failed logins from IP 2 (should not trigger)
        for (int i = 0; i < THRESHOLD - 1; i++) {
            Event event = new Event(2000 + (i * 100), "192.168.1.2", "bob", "LOGIN_FAIL", "web", new HashMap<>());
            List<Alert> alerts = rule.onEvent(event);
            assertTrue("IP 2 should not trigger alert yet", alerts.isEmpty());
        }
    }

    @Test
    public void testLoginSuccessNotCounted() {
        // Add 5 LOGIN_SUCCESS events (should not trigger alert)
        for (int i = 0; i < THRESHOLD; i++) {
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "LOGIN_SUCCESS", "web", new HashMap<>());
            List<Alert> alerts = rule.onEvent(event);
            assertTrue("LOGIN_SUCCESS should not trigger alert", alerts.isEmpty());
        }
    }

    @Test
    public void testMixedLoginActions() {
        // Add 3 failed logins
        for (int i = 0; i < 3; i++) {
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>());
            rule.onEvent(event);
        }
        
        // Add 2 successful logins
        for (int i = 0; i < 2; i++) {
            Event event = new Event(1300 + (i * 100), "192.168.1.1", "alice", "LOGIN_SUCCESS", "web", new HashMap<>());
            rule.onEvent(event);
        }
        
        // Total is 5 events but only 3 are LOGIN_FAIL, should not trigger
        Event finalEvent = new Event(1500, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>());
        List<Alert> alerts = rule.onEvent(finalEvent);
        
        // Now we have 4 LOGIN_FAILs, still below threshold
        assertTrue("Only 4 LOGIN_FAIL events, below threshold", alerts.isEmpty());
    }

    @Test
    public void testWindowExpiration() {
        // Add events within window
        for (int i = 0; i < THRESHOLD; i++) {
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>());
            rule.onEvent(event);
        }
        
        // Add event well beyond window (should clear old events)
        Event expiredEvent = new Event(1000 + WINDOW_MS + 1000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>());
        List<Alert> alerts = rule.onEvent(expiredEvent);
        
        // Only 1 event in window now, below threshold
        assertTrue("Expired events should be removed", alerts.isEmpty());
    }
}
