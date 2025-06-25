package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

public class BurpExtender implements IBurpExtender, ITab {

    private IBurpExtenderCallbacks callbacks;
    private CvssTab cvssTab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("CVSS v3.1 Calculator");

        SwingUtilities.invokeLater(() -> {
            cvssTab = new CvssTab();
            callbacks.addSuiteTab(BurpExtender.this);
        });
    }

    @Override
    public String getTabCaption() {
        return "CVSS Calculator";
    }

    @Override
    public Component getUiComponent() {
        return cvssTab;
    }
}

class CvssTab extends JPanel {

    private final JTextField vectorStringField;
    private final JLabel baseScoreLabel;
    private final Map<String, ButtonGroup> metricGroups = new HashMap<>();
    private final Map<String, String> currentSelections = new HashMap<>();
    private static final String CVSS_VERSION = "CVSS:3.1";
    private int metricRowCounter = 1;

    public CvssTab() {
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));
        setBackground(new Color(245, 245, 245));

        JPanel vectorPanel = new JPanel(new BorderLayout(10, 10));
        vectorPanel.setBorder(BorderFactory.createTitledBorder("Vector String"));
        vectorStringField = new JTextField("CVSS:3.1");
        vectorStringField.setEditable(false);
        vectorStringField.setFont(new Font("Monospaced", Font.PLAIN, 14));
        vectorPanel.add(vectorStringField, BorderLayout.CENTER);
        add(vectorPanel, BorderLayout.NORTH);

        JPanel metricsPanel = new JPanel(new GridBagLayout());
        metricsPanel.setBackground(Color.WHITE);
        metricsPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(""),
                new EmptyBorder(10, 10, 10, 10)
        ));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 4;
        JPanel baseScorePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        baseScorePanel.setBackground(Color.WHITE);
        baseScorePanel.add(new JLabel("Base Score"));
        baseScoreLabel = new JLabel("0.0 (None)");
        baseScoreLabel.setOpaque(true);
        baseScoreLabel.setBackground(new Color(200, 200, 200));
        baseScoreLabel.setForeground(Color.BLACK);
        baseScoreLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        baseScoreLabel.setBorder(new EmptyBorder(5, 10, 5, 10));
        baseScorePanel.add(baseScoreLabel);
        metricsPanel.add(baseScorePanel, gbc);

        gbc.gridwidth = 1;

        addMetric(metricsPanel, gbc, "Attack Vector", "AV", new String[]{"Network", "Adjacent", "Local", "Physical"}, new String[]{"N", "A", "L", "P"});
        addMetric(metricsPanel, gbc, "Scope", "S", new String[]{"Unchanged", "Changed"}, new String[]{"U", "C"});
        addMetric(metricsPanel, gbc, "Attack Complexity", "AC", new String[]{"Low", "High"}, new String[]{"L", "H"});
        addMetric(metricsPanel, gbc, "Confidentiality", "C", new String[]{"None", "Low", "High"}, new String[]{"N", "L", "H"});
        addMetric(metricsPanel, gbc, "Privileges Required", "PR", new String[]{"None", "Low", "High"}, new String[]{"N", "L", "H"});
        addMetric(metricsPanel, gbc, "Integrity", "I", new String[]{"None", "Low", "High"}, new String[]{"N", "L", "H"});
        addMetric(metricsPanel, gbc, "User Interaction", "UI", new String[]{"None", "Required"}, new String[]{"N", "R"});
        addMetric(metricsPanel, gbc, "Availability", "A", new String[]{"None", "Low", "High"}, new String[]{"N", "L", "H"});

        add(metricsPanel, BorderLayout.CENTER);
        initializeDefaults();
    }

    private void addMetric(JPanel panel, GridBagConstraints gbc, String label, String abbr, String[] options, String[] values) {
        gbc.gridx = 0;
        gbc.gridy = metricRowCounter++;
        gbc.anchor = GridBagConstraints.EAST;
        panel.add(new JLabel(label), gbc);

        gbc.gridx = 1;
        gbc.anchor = GridBagConstraints.WEST;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        buttonPanel.setBackground(Color.WHITE);
        ButtonGroup group = new ButtonGroup();
        metricGroups.put(abbr, group);

        for (int i = 0; i < options.length; i++) {
            JToggleButton button = new JToggleButton(options[i]);
            button.setActionCommand(values[i]);
            button.setFocusPainted(false);
            button.addActionListener(this::onMetricChange);
            group.add(button);
            buttonPanel.add(button);
        }
        panel.add(buttonPanel, gbc);
    }

    private void initializeDefaults() {
        selectButton("AV", "N");
        selectButton("AC", "L");
        selectButton("PR", "N");
        selectButton("UI", "N");
        selectButton("S", "U");
        selectButton("C", "N");
        selectButton("I", "N");
        selectButton("A", "N");
        updateCvss();
    }

    private void selectButton(String groupAbbr, String value) {
        ButtonGroup group = metricGroups.get(groupAbbr);
        for (AbstractButton button : java.util.Collections.list(group.getElements())) {
            if (button.getActionCommand().equals(value)) {
                button.setSelected(true);
                currentSelections.put(groupAbbr, value);
                updateButtonColors((JToggleButton) button, true);
                break;
            }
        }
    }

    private void onMetricChange(ActionEvent e) {
        JToggleButton source = (JToggleButton) e.getSource();
        if (source.isSelected()) {
            ButtonGroup group = findGroupForButton(source);
            if (group != null) {
                String abbr = findAbbrForGroup(group);
                if (abbr != null) {
                    currentSelections.put(abbr, source.getActionCommand());
                }
                for (AbstractButton button : java.util.Collections.list(group.getElements())) {
                    updateButtonColors((JToggleButton) button, button == source);
                }
                updateCvss();
            }
        } else {
            source.setSelected(true);
        }
    }

    private void updateButtonColors(JToggleButton button, boolean isSelected) {
        if (isSelected) {
            button.setBackground(new Color(46, 139, 87));
            button.setForeground(Color.WHITE);
        } else {
            button.setBackground(UIManager.getColor("Button.background"));
            button.setForeground(UIManager.getColor("Button.foreground"));
        }
    }

    private ButtonGroup findGroupForButton(JToggleButton button) {
        for (ButtonGroup group : metricGroups.values()) {
            if (java.util.Collections.list(group.getElements()).contains(button)) {
                return group;
            }
        }
        return null;
    }

    private String findAbbrForGroup(ButtonGroup group) {
        for (Map.Entry<String, ButtonGroup> entry : metricGroups.entrySet()) {
            if (entry.getValue().equals(group)) {
                return entry.getKey();
            }
        }
        return null;
    }

    private void updateCvss() {
        if (currentSelections.size() < 8) return;

        StringJoiner vector = new StringJoiner("/");
        vector.add(CVSS_VERSION);
        vector.add("AV:" + currentSelections.get("AV"));
        vector.add("AC:" + currentSelections.get("AC"));
        vector.add("PR:" + currentSelections.get("PR"));
        vector.add("UI:" + currentSelections.get("UI"));
        vector.add("S:" + currentSelections.get("S"));
        vector.add("C:" + currentSelections.get("C"));
        vector.add("I:" + currentSelections.get("I"));
        vector.add("A:" + currentSelections.get("A"));

        vectorStringField.setText(vector.toString());

        CvssV31Calculator.Score score = CvssV31Calculator.calculate(vector.toString());
        updateScoreLabel(score.baseScore, score.severity);
    }

    private void updateScoreLabel(double score, String severity) {
        baseScoreLabel.setText(String.format("%.1f (%s)", score, severity));
        Color color;
        switch (severity) {
            case "None": color = new Color(82, 179, 217); break;
            case "Low": color = new Color(255, 204, 0); break;
            case "Medium": color = new Color(255, 153, 0); break;
            case "High": color = new Color(255, 87, 34); break;
            case "Critical": color = new Color(205, 0, 0); break;
            default: color = Color.LIGHT_GRAY;
        }
        baseScoreLabel.setBackground(color);
        baseScoreLabel.setForeground(severity.equals("Low") || severity.equals("Medium") ? Color.BLACK : Color.WHITE);
    }
}

class CvssV31Calculator {

    private static final Map<String, Double> ATTACK_VECTOR_MAP = Map.of("N", 0.85, "A", 0.62, "L", 0.55, "P", 0.2);
    private static final Map<String, Double> ATTACK_COMPLEXITY_MAP = Map.of("L", 0.77, "H", 0.44);
    private static final Map<String, Map<String, Double>> PRIVILEGES_REQUIRED_MAP = Map.of(
            "U", Map.of("N", 0.85, "L", 0.62, "H", 0.27),
            "C", Map.of("N", 0.85, "L", 0.68, "H", 0.50)
    );
    private static final Map<String, Double> USER_INTERACTION_MAP = Map.of("N", 0.85, "R", 0.62);
    private static final Map<String, Double> CIA_MAP = Map.of("H", 0.56, "L", 0.22, "N", 0.0);

    public static class Score {
        public final double baseScore;
        public final String severity;
        Score(double baseScore, String severity) {
            this.baseScore = baseScore;
            this.severity = severity;
        }
    }

    private static double roundup(double d) {
        return Math.ceil(d * 100000) / 100000.0;
    }

    public static Score calculate(String vector) {
        Map<String, String> metrics = new HashMap<>();
        String[] parts = vector.split("/");
        for (int i = 1; i < parts.length; i++) {
            String[] metric = parts[i].split(":");
            metrics.put(metric[0], metric[1]);
        }

        double confidentiality = CIA_MAP.get(metrics.get("C"));
        double integrity = CIA_MAP.get(metrics.get("I"));
        double availability = CIA_MAP.get(metrics.get("A"));
        double impactSubScore = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability));

        double attackVector = ATTACK_VECTOR_MAP.get(metrics.get("AV"));
        double attackComplexity = ATTACK_COMPLEXITY_MAP.get(metrics.get("AC"));
        double privilegesRequired = PRIVILEGES_REQUIRED_MAP.get(metrics.get("S")).get(metrics.get("PR"));
        double userInteraction = USER_INTERACTION_MAP.get(metrics.get("UI"));
        double exploitabilitySubScore = 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction;

        double baseScore;
        if (impactSubScore <= 0) {
            baseScore = 0.0;
        } else if (metrics.get("S").equals("U")) {
            baseScore = roundup(Math.min(impactSubScore + exploitabilitySubScore, 10));
        } else {
            baseScore = roundup(Math.min(1.08 * (impactSubScore + exploitabilitySubScore), 10));
        }

        return new Score(baseScore, getSeverity(baseScore));
    }

    private static String getSeverity(double score) {
        if (score == 0.0) return "None";
        if (score <= 3.9) return "Low";
        if (score <= 6.9) return "Medium";
        if (score <= 8.9) return "High";
        return "Critical";
    }
}
