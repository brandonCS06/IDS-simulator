package com.ids;

import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

/**
 * Canonical representation of a single log event that the IDS
 * processes. Events are produced by the Python log parser and fed into
 * the Java engine for rule evaluation.
 *
 * Each event captures when something happened, which IP/user performed
 * the action, what the action was, which target it affected, and any
 * additional metadata as a free-form map.
 */
public class Event {
    private long timestamp;
    private String source_ip;
    private String user;
    private String action;
    private String target;
    private Map<String, Object> metadata;

    /**
     * Shared Gson instance for serializing and deserializing events in
     * a stable, pretty-printed JSON form.
     */
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .serializeNulls()
            .create(); 

    /**
     * Construct a new event instance matching the normalized schema
     * emitted by the Python log parser.
     *
     * @param timestamp time the event occurred (epoch millis)
     * @param source_ip IP address that originated the event
     * @param user      user identity associated with the event
     * @param action    high-level action name (e.g. login, access)
     * @param target    resource or service being acted upon
     * @param metadata  additional contextual fields for this event
     */
    public Event(long timestamp, String source_ip, String user, String action, String target, Map<String, Object> metadata) {
        this.timestamp = timestamp;
        this.source_ip = source_ip;
        this.user = user;
        this.action = action;
        this.target = target;
        this.metadata = metadata;
    }

    public long getTimestamp() {
        return timestamp;
    }
    
    public String getSource_ip() {
        return source_ip;
    }

    public String getUser() {
        return user;
    }

    public String getAction() {
        return action;
    }

    public String getTarget() {
        return target;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /**
     * Serialize this event into JSON. Used when persisting events or
     * passing them to external tools for analysis.
     */
    public String toJson()
    {
        return gson.toJson(this);
    }

    /**
     * Reconstruct a single {@link Event} from its JSON representation.
     *
     * This is the inverse of {@link #toJson()} for one event.
     */
    public static Event fromJson(String json)
    {
        return gson.fromJson(json,Event.class);
    }

    /**
     * Deserialize a JSON array of events into a Java {@code List}.
     *
     * Useful when loading the `Events.json` file produced by the
     * Python log parser into memory for rule processing.
     */
    public static List<Event> fromJsonArray(String json) {
        Type listType = new TypeToken<List<Event>>(){}.getType();
        return gson.fromJson(json, listType);
    }
}
