package com.ids;

import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

public class Event {
    private long timestamp;
    private String source_ip;
    private String user;
    private String action;
    private String target;
    private Map<String, Object> metadata;

    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .serializeNulls()
            .create(); 

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

    public String toJson()
    {
        return gson.toJson(this);
    }

    public static Event fromJson(String json)
    {
        return gson.fromJson(json,Event.class);
    }

    public static List<Event> fromJsonArray(String json) {
        Type listType = new TypeToken<List<Event>>(){}.getType();
        return gson.fromJson(json, listType);
    }
}
