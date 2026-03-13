package com.ids;
import java.util.ArrayList;
import java.util.List;

public class RuleEngine {
    private List<RuleEngineRules> rules;

    public RuleEngine()
    {
        this.rules = new ArrayList<>();
    }

    public void registerRule(RuleEngineRules rule)
    {
        if (rule != null && !rules.contains(rule)){
            this.rules.add(rule);
        }
    }

    public List<Alert> processEvent(List<Event> events)
    {
        List<Alert> alerts = new ArrayList<>(); //Accumulate all alerts

        for (Event event : events) {
            for (RuleEngineRules rule : rules) { //For each event, check the rules
                List<Alert> ruleAlerts = rule.onEvent(event); //get alerts from the rule
                if (ruleAlerts != null && !ruleAlerts.isEmpty()) {
                    alerts.addAll(ruleAlerts);
                }
            }
        }
        return alerts;
    }


}
