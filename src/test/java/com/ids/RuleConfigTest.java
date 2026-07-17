package com.ids;

import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class RuleConfigTest {

    @Test
    public void testLoadPartialConfigKeepsDefaults() throws Exception {
        File configFile = writeTempFile(
            "{\n" +
            "  \"port_scan\": {\n" +
            "    \"port_threshold\": 3\n" +
            "  },\n" +
            "  \"syn_flood\": {\n" +
            "    \"syn_threshold\": 10,\n" +
            "    \"max_ack_ratio\": 0.5\n" +
            "  }\n" +
            "}\n"
        );

        RuleConfig config = RuleConfig.load(configFile.getAbsolutePath());

        assertEquals(5, config.brute_force.threshold);
        assertEquals(60_000L, config.brute_force.window_ms);
        assertEquals(3, config.port_scan.port_threshold);
        assertEquals(60_000L, config.port_scan.window_ms);
        assertEquals(10, config.syn_flood.syn_threshold);
        assertEquals(30, config.syn_flood.minimum_syn_for_ratio);
        assertEquals(0.5d, config.syn_flood.max_ack_ratio, 0.0001d);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidConfigValueFailsFast() throws Exception {
        File configFile = writeTempFile(
            "{\n" +
            "  \"brute_force\": {\n" +
            "    \"threshold\": 0\n" +
            "  }\n" +
            "}\n"
        );

        RuleConfig.load(configFile.getAbsolutePath());
    }

    @Test
    public void testIdsCoreUsesConfiguredThresholds() throws Exception {
        RuleConfig config = RuleConfig.defaults();
        config.brute_force.threshold = 2;

        File eventsFile = writeTempFile(
            "[\n" +
            "  {\"timestamp\":1000,\"source_ip\":\"192.168.1.1\",\"user\":\"alice\",\"action\":\"LOGIN_FAIL\",\"target\":\"web\",\"metadata\":{}},\n" +
            "  {\"timestamp\":1100,\"source_ip\":\"192.168.1.1\",\"user\":\"alice\",\"action\":\"LOGIN_FAIL\",\"target\":\"web\",\"metadata\":{}}\n" +
            "]\n"
        );

        IDSCore core = new IDSCore(config);
        core.loadEvents(eventsFile.getAbsolutePath());
        core.processEvents();

        List<Alert> alerts = core.getAlerts();
        assertFalse(alerts.isEmpty());
        assertEquals("BruteForceRule", alerts.get(0).getRule_name());
        assertEquals(Integer.valueOf(2), alerts.get(0).getMetrics().get("threshold"));
    }

    @Test
    public void testCustomPortScanThreshold() {
        PortScanRule rule = new PortScanRule(60_000L, 3);
        List<Alert> alerts = null;

        for (int i = 0; i < 3; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("destination_port", Integer.valueOf(8000 + i));
            Event event = new Event(1000L + (i * 100L), "10.0.0.5", "alice", "PROBE", "web", metadata);
            alerts = rule.onEvent(event);
        }

        assertFalse(alerts.isEmpty());
        assertEquals(Integer.valueOf(3), alerts.get(0).getMetrics().get("threshold"));
        assertEquals(Integer.valueOf(3), alerts.get(0).getMetrics().get("unique_destination_ports"));
    }

    private File writeTempFile(String content) throws Exception {
        File file = File.createTempFile("ids-config-test", ".json");
        file.deleteOnExit();
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
        return file;
    }
}
