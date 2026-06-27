package com.ids;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import java.util.HashMap;
import java.util.Map;

public class EventTest {

    private Map<String, Object> metadata;
    private Event event;

    @Before
    public void setUp() {
        metadata = new HashMap<>();
        metadata.put("protocol", "TCP");
        metadata.put("destination_port", 22);
        
        event = new Event(
            1000L,
            "192.168.1.1",
            "alice",
            "LOGIN_FAIL",
            "web_server",
            metadata
        );
    }

    @Test
    public void testEventCreation() {
        assertNotNull(event);
        assertEquals(1000L, event.getTimestamp());
        assertEquals("192.168.1.1", event.getSource_ip());
        assertEquals("alice", event.getUser());
        assertEquals("LOGIN_FAIL", event.getAction());
        assertEquals("web_server", event.getTarget());
        assertNotNull(event.getMetadata());
    }

    @Test
    public void testEventGetters() {
        assertEquals("TCP", event.getProtocol());
        assertEquals(Integer.valueOf(22), event.getDestinationPort());
    }

    @Test
    public void testEventWithNullMetadata() {
        Event eventNoMeta = new Event(2000L, "10.0.0.1", "bob", "LOGIN_SUCCESS", "db", null);
        assertNull(eventNoMeta.getProtocol());
        assertNull(eventNoMeta.getDestinationPort());
    }

    @Test
    public void testEventWithStringPort() {
        metadata.put("destination_port", "443");
        Event eventStringPort = new Event(3000L, "10.0.0.2", "charlie", "ACCESS_DENIED", "api", metadata);
        assertEquals(Integer.valueOf(443), eventStringPort.getDestinationPort());
    }

    @Test
    public void testEventWithMissingPortMetadata() {
        Event eventNoPort = new Event(4000L, "10.0.0.3", "diana", "LOGIN_FAIL", "web", new HashMap<>());
        assertNull(eventNoPort.getDestinationPort());
    }
}
