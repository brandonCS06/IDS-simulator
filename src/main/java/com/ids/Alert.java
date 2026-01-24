package com.ids;

import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Alert implements Comparable<Alert> {
    private long timestamp;
    private String rule_name;
    private String severity;
    private List<Event> evidence;
    private String source_ip;


    public static final Gson gson = new GsonBuilder()
                .setPrettyPrinting()
                .serializeNulls()
                .create();

    public Alert (long timestamp, String rule_name, String severity, List<Event> evidence, String source_ip)
    {
        this.timestamp = timestamp;
        this.rule_name = rule_name;
        this.severity = severity;
        this.evidence = evidence;
        this.source_ip = source_ip;
    }

    public long getTimestamp()
    {
        return timestamp;
    }

    public String getRule_name()
    {
        return rule_name;
    }

    public String getSeverity()
    {
        return severity;
    }

    public List<Event> getEvidence()
    {
        return evidence;
    }

    public String getSource_ip()
    {
        return source_ip;
    }

    public int compareTo(Alert other)
    {

        int thisSeverity = getSeverityPriority(this.severity);
        int otherSeverity = getSeverityPriority(other.severity);
        int result = Integer.compare(otherSeverity,thisSeverity);

       
        if(result != 0) 
            return result;

        //Compares timestamps if severity is equal
        return Long.compare(this.timestamp, other.timestamp);


    }

    private int getSeverityPriority(String severity)
    {
        if(severity == null)
        {
            return 0;
        }

        switch(severity.toLowerCase())
        {
            case "low":
                return 1;
            case "medium":
                return 2;
            case "med":
                return 2;
            case "high":
                return 3;
            case "critical":
                return 4;
            default:
                return 0;
        }
    }

    public String toJson()
    {
        return gson.toJson(this);
    }
    
}
