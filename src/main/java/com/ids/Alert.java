package com.ids;

import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Represents a single IDS alert produced by applying detection rules
 * over one or more underlying {@link Event} objects.
 *
 * An alert carries the rule that fired, the severity, the source IP it
 * is associated with, and the list of supporting events. Alerts are
 * comparable so they can be sorted by severity (descending) and then
 * by timestamp (ascending) for triage.
 */
public class Alert implements Comparable<Alert> {
    private long timestamp;
    private String rule_name;
    private String severity;
    private List<Event> evidence;
    private String source_ip;
    private String description;
    private String recommendation;
    private Map<String, Object> metrics;


    /**
     * Shared Gson instance for serializing alerts to JSON for logging
     * or downstream tools (pretty-printed and including nulls).
     */
    public static final Gson gson = new GsonBuilder()
                .setPrettyPrinting()
                .serializeNulls()
                .create();

    /**
     * Construct a new alert instance describing a rule hit.
     *
     * @param timestamp the time the alert was raised (epoch millis)
     * @param rule_name the name/identifier of the rule that triggered
     * @param severity  normalized severity string (e.g. low/med/high)
     * @param evidence  list of events that caused or support the alert
     * @param source_ip IP address this alert is attributed to
     */
    public Alert (long timestamp, String rule_name, String severity, List<Event> evidence, String source_ip)
    {
        this(timestamp, rule_name, severity, evidence, source_ip, null, null, null);
    }

    /**
     * Construct a new alert with human-readable context and computed
     * detection metrics. These optional fields make JSON output easier
     * to explain in demos and reports while preserving the original schema.
     *
     * @param timestamp      the time the alert was raised (epoch millis)
     * @param rule_name      the name/identifier of the rule that triggered
     * @param severity       normalized severity string (e.g. low/med/high)
     * @param evidence       list of events that caused or support the alert
     * @param source_ip      IP address this alert is attributed to
     * @param description    short explanation of why the rule fired
     * @param recommendation analyst-facing follow-up or learning note
     * @param metrics        computed values that support the alert
     */
    public Alert (
        long timestamp,
        String rule_name,
        String severity,
        List<Event> evidence,
        String source_ip,
        String description,
        String recommendation,
        Map<String, Object> metrics
    )
    {
        this.timestamp = timestamp;
        this.rule_name = rule_name;
        this.severity = severity;
        this.evidence = evidence;
        this.source_ip = source_ip;
        this.description = description;
        this.recommendation = recommendation;
        this.metrics = metrics;
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

    public String getDescription()
    {
        return description;
    }

    public String getRecommendation()
    {
        return recommendation;
    }

    public Map<String, Object> getMetrics()
    {
        return metrics;
    }

    /**
     * Order alerts by severity (highest first) and then timestamp
     * (earliest first) when severities are equal.
     *
     * This allows prioritized sorting so that critical and high alerts
     * float to the top of analyst views.
     */
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

    /**
     * Map a severity label to a sortable priority where larger values
     * indicate more urgent alerts.
     *
     * Unknown or null severities are treated as lowest priority.
     */
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

    /**
     * Serialize this alert into a JSON string using the shared Gson
     * configuration. Useful for output files and debugging.
     */
    public String toJson()
    {
        return gson.toJson(this);
    }
    
}
