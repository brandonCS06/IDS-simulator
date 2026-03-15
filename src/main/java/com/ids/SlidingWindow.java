package com.ids;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tracks events per source IP over a fixed time window.
 *
 * Assumes events are added in roughly non-decreasing timestamp order.
 */
public class SlidingWindow {
    private final long windowMillis;
    private final Map<String, Deque<Event>> buckets = new HashMap<>();
    private long lastSeenTimestamp = Long.MIN_VALUE;

    public SlidingWindow(long windowMillis) {
        if (windowMillis <= 0) {
            throw new IllegalArgumentException("windowMillis must be positive");
        }
        this.windowMillis = windowMillis;
    }

    /**
     * Add an event to the window (bucketed by source IP).
     */
    public void addEvent(Event event) {
        if (event == null) {
            return;
        }
        lastSeenTimestamp = Math.max(lastSeenTimestamp, event.getTimestamp());
        Deque<Event> deque = buckets.computeIfAbsent(event.getSource_ip(), k -> new ArrayDeque<>());
        deque.addLast(event);
        removeExpiredForBucket(deque);
    }

    /**
     * Remove expired events across all buckets using the last seen timestamp.
     */
    public void removeExpired() {
        if (lastSeenTimestamp == Long.MIN_VALUE) {
            return;
        }
        for (Deque<Event> deque : buckets.values()) {
            removeExpiredForBucket(deque);
        }
    }

    /**
     * Count all events in-window for a given source IP.
     */
    public int count(String sourceIp) {
        Deque<Event> deque = buckets.get(sourceIp);
        if (deque == null) {
            return 0;
        }
        removeExpiredForBucket(deque);
        return deque.size();
    }

    /**
     * Count events in-window for a given source IP and action type.
     */
    public int count(String sourceIp, String action) {
        Deque<Event> deque = buckets.get(sourceIp);
        if (deque == null) {
            return 0;
        }
        removeExpiredForBucket(deque);
        if (action == null) {
            return deque.size();
        }
        int total = 0;
        for (Event event : deque) {
            if (action.equalsIgnoreCase(event.getAction())) {
                total++;
            }
        }
        return total;
    }

    private void removeExpiredForBucket(Deque<Event> deque) {
        long cutoff = lastSeenTimestamp - windowMillis;
        while (!deque.isEmpty() && deque.peekFirst().getTimestamp() < cutoff) {
            deque.removeFirst();
        }
    }

    public List<Event> getEvents(String sourceIp, String action) {
        Deque<Event> deque = buckets.get(sourceIp);
        if (deque == null) {
            return new ArrayList<>();  // No events for this IP
        }
        
        removeExpiredForBucket(deque);  // Prune expired events
        List<Event> result = new ArrayList<>();
        
        for (Event event : deque) {
            if (action == null || action.equalsIgnoreCase(event.getAction())) {
            result.add(event);
            }
        }
        return result;
    }
}
