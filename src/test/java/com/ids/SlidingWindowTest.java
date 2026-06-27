package com.ids;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import java.util.HashMap;
import java.util.List;

public class SlidingWindowTest {

    private SlidingWindow window;
    private static final long WINDOW_MS = 60_000; // 60 seconds

    @Before
    public void setUp() {
        window = new SlidingWindow(WINDOW_MS);
    }

    @Test
    public void testWindowCreation() {
        assertNotNull(window);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidWindowSize() {
        new SlidingWindow(0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNegativeWindowSize() {
        new SlidingWindow(-1);
    }

    @Test
    public void testAddEventAndCount() {
        Event event = new Event(1000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>());
        window.addEvent(event);
        
        assertEquals(1, window.count("192.168.1.1"));
    }

    @Test
    public void testCountMultipleEvents() {
        window.addEvent(new Event(1000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        window.addEvent(new Event(1500, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        window.addEvent(new Event(2000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        
        assertEquals(3, window.count("192.168.1.1"));
    }

    @Test
    public void testCountByAction() {
        window.addEvent(new Event(1000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        window.addEvent(new Event(1500, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        window.addEvent(new Event(2000, "192.168.1.1", "alice", "LOGIN_SUCCESS", "web", new HashMap<>()));
        
        assertEquals(2, window.count("192.168.1.1", "LOGIN_FAIL"));
        assertEquals(1, window.count("192.168.1.1", "LOGIN_SUCCESS"));
    }

    @Test
    public void testWindowExpiration() {
        // Add event at time 1000
        window.addEvent(new Event(1000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        assertEquals(1, window.count("192.168.1.1"));
        
        // Add event beyond window (1000 + 60_000 + 1)
        window.addEvent(new Event(61_001, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        
        // Old event should be expired, only new one should remain
        assertEquals(1, window.count("192.168.1.1"));
    }

    @Test
    public void testMultipleIPs() {
        window.addEvent(new Event(1000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        window.addEvent(new Event(1500, "192.168.1.2", "bob", "LOGIN_FAIL", "web", new HashMap<>()));
        window.addEvent(new Event(2000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        
        assertEquals(2, window.count("192.168.1.1"));
        assertEquals(1, window.count("192.168.1.2"));
    }

    @Test
    public void testCountNonexistentIP() {
        assertEquals(0, window.count("192.168.1.99"));
    }

    @Test
    public void testNullEvent() {
        window.addEvent(null);
        assertEquals(0, window.count("any_ip"));
    }

    @Test
    public void testGetEventsForIP() {
        window.addEvent(new Event(1000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        window.addEvent(new Event(1500, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        
        List<Event> events = window.getEvents("192.168.1.1", "LOGIN_FAIL");
        assertNotNull(events);
        assertEquals(2, events.size());
    }

    @Test
    public void testGetEventsNonexistentIP() {
        List<Event> events = window.getEvents("192.168.1.99", "LOGIN_FAIL");
        assertNotNull(events);
        assertEquals(0, events.size());
    }
}
