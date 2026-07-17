package com.ids;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class AlertTest {

    private Alert alert;
    private List<Event> evidence;

    @Before
    public void setUp() {
        evidence = new ArrayList<>();
        evidence.add(new Event(1000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        evidence.add(new Event(1100, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        
        alert = new Alert(1500L, "BruteForceRule", "high", evidence, "192.168.1.1");
    }

    @Test
    public void testAlertCreation() {
        assertNotNull(alert);
    }

    @Test
    public void testAlertGetters() {
        assertEquals(1500L, alert.getTimestamp());
        assertEquals("BruteForceRule", alert.getRule_name());
        assertEquals("high", alert.getSeverity());
        assertEquals("192.168.1.1", alert.getSource_ip());
        assertNotNull(alert.getEvidence());
        assertEquals(2, alert.getEvidence().size());
        assertNull(alert.getDescription());
        assertNull(alert.getRecommendation());
        assertNull(alert.getMetrics());
    }

    @Test
    public void testAlertWithExplanationAndMetrics() {
        HashMap<String, Object> metrics = new HashMap<String, Object>();
        metrics.put("failed_login_count", Integer.valueOf(5));
        metrics.put("threshold", Integer.valueOf(5));

        Alert richAlert = new Alert(
            1500L,
            "BruteForceRule",
            "high",
            evidence,
            "192.168.1.1",
            "Source crossed the failed login threshold.",
            "Review authentication logs.",
            metrics
        );

        assertEquals("Source crossed the failed login threshold.", richAlert.getDescription());
        assertEquals("Review authentication logs.", richAlert.getRecommendation());
        assertNotNull(richAlert.getMetrics());
        assertEquals(Integer.valueOf(5), richAlert.getMetrics().get("failed_login_count"));
        assertTrue(richAlert.toJson().contains("description"));
        assertTrue(richAlert.toJson().contains("metrics"));
    }

    @Test
    public void testAlertWithEmptyEvidence() {
        Alert emptyAlert = new Alert(2000L, "TestRule", "medium", new ArrayList<>(), "10.0.0.1");
        assertNotNull(emptyAlert.getEvidence());
        assertEquals(0, emptyAlert.getEvidence().size());
    }

    @Test
    public void testAlertWithNullEvidence() {
        Alert nullAlert = new Alert(2000L, "TestRule", "low", null, "10.0.0.1");
        assertNull(nullAlert.getEvidence());
    }

    @Test
    public void testAlertSeverityValues() {
        Alert highAlert = new Alert(1000L, "Rule1", "high", evidence, "192.168.1.1");
        Alert mediumAlert = new Alert(1000L, "Rule2", "medium", evidence, "192.168.1.1");
        Alert lowAlert = new Alert(1000L, "Rule3", "low", evidence, "192.168.1.1");
        
        assertEquals("high", highAlert.getSeverity());
        assertEquals("medium", mediumAlert.getSeverity());
        assertEquals("low", lowAlert.getSeverity());
    }

    @Test
    public void testMultipleAlertsWithDifferentRules() {
        Alert bruteForceAlert = new Alert(1000L, "BruteForceRule", "high", evidence, "192.168.1.1");
        Alert portScanAlert = new Alert(2000L, "PortScanRule", "high", evidence, "192.168.1.2");
        
        assertEquals("BruteForceRule", bruteForceAlert.getRule_name());
        assertEquals("PortScanRule", portScanAlert.getRule_name());
        assertNotEquals(bruteForceAlert.getSource_ip(), portScanAlert.getSource_ip());
    }
}
