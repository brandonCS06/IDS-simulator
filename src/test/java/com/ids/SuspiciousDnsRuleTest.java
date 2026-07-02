package com.ids;

import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class SuspiciousDnsRuleTest {

    private SuspiciousDnsRule rule;
    private static final int EVENT_THRESHOLD = 5;

    @Before
    public void setUp() {
        rule = new SuspiciousDnsRule();
    }

    @Test
    public void testRuleCreation() {
        assertNotNull(rule);
        assertEquals("SuspiciousDnsRule", rule.getName());
    }

    @Test
    public void testNonDnsEventIgnored() {
        Event event = new Event(1000, "192.168.1.1", "alice", "LOGIN_SUCCESS", "web", new HashMap<String, Object>());
        List<Alert> alerts = rule.onEvent(event);

        assertNotNull(alerts);
        assertTrue(alerts.isEmpty());
    }

    @Test
    public void testBelowThresholdNoAlert() {
        for (int i = 0; i < EVENT_THRESHOLD - 1; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("protocol", "DNS");
            metadata.put("query_name", "token" + i + ".exfil.example.com");
            metadata.put("qtype", "TXT");
            metadata.put("rcode", "NXDOMAIN");
            metadata.put("response_size", 120);
            metadata.put("label_length", 16 + i);
            metadata.put("entropy", 4.6);

            Event event = new Event(1000 + (i * 200), "10.0.0.5", "alice", "DNS_QUERY", "dns_resolver", metadata);
            List<Alert> alerts = rule.onEvent(event);

            assertTrue("Alert should not trigger below the minimum event count", alerts.isEmpty());
        }
    }

    @Test
    public void testSuspiciousDnsDetection() {
        for (int i = 0; i < EVENT_THRESHOLD; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("protocol", "DNS");
            metadata.put("query_name", "averylongtokensegment" + i + ".exfil.example.com");
            metadata.put("qtype", "TXT");
            metadata.put("rcode", i == EVENT_THRESHOLD - 1 ? "NXDOMAIN" : "NOERROR");
            metadata.put("response_size", 600);
            metadata.put("label_length", 24 + i);
            metadata.put("entropy", 4.8);

            Event event = new Event(1000 + (i * 250), "10.0.0.5", "alice", "DNS_QUERY", "dns_resolver", metadata);
            List<Alert> alerts = rule.onEvent(event);

            if (i < EVENT_THRESHOLD - 1) {
                assertTrue("Alert should not trigger until threshold is reached", alerts.isEmpty());
            } else {
                assertFalse("Alert should trigger at threshold", alerts.isEmpty());
                assertEquals(1, alerts.size());
                Alert alert = alerts.get(0);
                assertEquals("SuspiciousDnsRule", alert.getRule_name());
                assertEquals("high", alert.getSeverity());
                assertEquals("10.0.0.5", alert.getSource_ip());
                assertNotNull(alert.getEvidence());
                assertTrue(alert.getEvidence().size() >= EVENT_THRESHOLD);
            }
        }
    }

    @Test
    public void testWindowExpiration() {
        for (int i = 0; i < EVENT_THRESHOLD; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("protocol", "DNS");
            metadata.put("query_name", "token" + i + ".exfil.example.com");
            metadata.put("qtype", "TXT");
            metadata.put("rcode", "NXDOMAIN");
            metadata.put("response_size", 120);
            metadata.put("label_length", 20 + i);
            metadata.put("entropy", 4.5);

            Event event = new Event(1000 + (i * 200), "10.0.0.5", "alice", "DNS_QUERY", "dns_resolver", metadata);
            rule.onEvent(event);
        }

        HashMap<String, Object> metadata = new HashMap<String, Object>();
        metadata.put("protocol", "DNS");
        metadata.put("query_name", "fresh-token.exfil.example.com");
        metadata.put("qtype", "TXT");
        metadata.put("rcode", "NXDOMAIN");
        metadata.put("response_size", 120);
        metadata.put("label_length", 20);
        metadata.put("entropy", 4.5);

        Event expiredEvent = new Event(1000 + 60_000 + 1000, "10.0.0.5", "alice", "DNS_QUERY", "dns_resolver", metadata);
        List<Alert> alerts = rule.onEvent(expiredEvent);

        assertTrue("Expired events should be removed from the window", alerts.isEmpty());
    }
}