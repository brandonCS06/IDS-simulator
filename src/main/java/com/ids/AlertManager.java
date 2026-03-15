package com.ids;
import java.util.List;
import java.util.ArrayList;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Collections;


public class AlertManager {
    private List<Alert> alerts;


    public AlertManager(List<Alert> alerts)
    {
        if(alerts != null){
            this.alerts = alerts;
        } else {
            this.alerts = new ArrayList<>();
        }
    }

    public void addAlert(Alert alert)
    {
        if(alert != null){
            this.alerts.add(alert);
        }
    }
   
    public void addAlerts(List<Alert> newAlerts)
    {
        if (newAlerts != null && !newAlerts.isEmpty()) {
            this.alerts.addAll(newAlerts);
        }
    }

    public void printAlerts()
    {
        if(alerts != null && !alerts.isEmpty()){
            Collections.sort(alerts);
            for(Alert alert : alerts){
                Date date = new Date(alert.getTimestamp());
                SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
                
                String formattedTime = sdf.format(date);

                System.out.println("[ALERT] " + alert.getRule_name() + " Source IP: " + alert.getSource_ip() +
                 " Severity: " + alert.getSeverity() + " Time: " + formattedTime);
             }
        }
    }
  
    public List<Alert> getAlerts() {
        return alerts;
    }

    public int size() {
        return alerts.size();
    }

    public void clearAlerts() {
        if (alerts != null) {
            alerts.clear();
        }
    }

    public void exportToJson(String filePath)
    {
        Collections.sort(alerts);
        try (FileWriter writer = new FileWriter(filePath)) {
            Alert.gson.toJson(alerts, writer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
