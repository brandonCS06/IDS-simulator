package com.ids;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.io.File;

public class IDSCore {
   private List<Event> events;
    private RuleEngine ruleEngine;
    private AlertManager alertManager;

    public IDSCore()
    {
        this.ruleEngine = new RuleEngine();
        this.alertManager = new AlertManager(null);

        registerDefaultRules();
    }

    public void registerDefaultRules()
    {
        //adds brute-force detection
        ruleEngine.registerRule(new BruteForceRule());
    }

    public void loadEvents(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IOException("Events file not found: " + filePath);
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder jsonBuilder = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                jsonBuilder.append(line);
            }
            
            String json = jsonBuilder.toString();
            this.events = Event.fromJsonArray(json);
            System.out.println("Loaded " + this.events.size() + " events from " + filePath);
        }   catch (IOException e) {
                System.err.println("Error loading events: " + e.getMessage());
                throw e;
            }
    }

    public void processEvents() {
        
        if (this.events == null || this.events.isEmpty()) {
            System.err.println("No events loaded. Call loadEvents() first.");
            return;
        }
        
        List<Alert> newAlerts = this.ruleEngine.processEvent(this.events);
        this.alertManager.addAlerts(newAlerts);
        System.out.println("Processed events and generated " + newAlerts.size() + " alerts.");
    }

    public void printAlerts()
    {
        this.alertManager.printAlerts();
    }

    public void exportAlerts(String filePath)
    {
        this.alertManager.exportToJson(filePath);
        System.out.println("Exported alerts to " + filePath);
    }

    public List<Alert> getAlerts(){
        return this.alertManager.getAlerts();
    }

    public void clearAlerts(){
        this.alertManager.clearAlerts();
    }

    public static void main(String[] args) {
        IDSCore core = new IDSCore();
        try {
            String eventsFile = args.length > 0 ? args[0] : "Events.json";
            core.loadEvents(eventsFile);
            core.processEvents();
            core.exportAlerts("Alerts.json");
            //Export to file
        } catch (IOException e) {
            System.err.println("Failed to run IDS Core: " + e.getMessage());
            System.exit(1);
        }
    }
}

   

