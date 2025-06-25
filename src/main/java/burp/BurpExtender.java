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
    private JSplitPane mainPanel;
    private CvssTab cvssTab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("CVSS v3.1 Calculator");

        SwingUtilities.invokeLater(() -> {
            cvssTab = new CvssTab();
            mainPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            mainPanel.setTopComponent(cvssTab);
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

    public CvssTab() {
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));
        setBackground(new Color(245, 245, 245));

        // --- Top Panel for Vector String ---
        JPanel vectorPanel = new JPanel(new BorderLayout(10, 10));
        vectorPanel.setBorder(BorderFactory.createTitledBorder("Vector String"));
        vectorStringField = new JTextField("CVSS:3.1");
        vectorStringField.setEditable(false);
        vectorStringField.setFont(new Font("Monospaced", Font.PLAIN, 14));
        vectorPanel.add(vectorStringField, BorderLayout.CENTER);
        add(vectorPanel, BorderLayout.NORTH);

        // --- Center Panel for Metrics ---
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

        // Base Score
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

        gbc.gridwidth = 1; // Reset gridwidth

        // Attack Vector
        addMetric(metricsPanel, gbc, 1, "Attack Vector", "AV",
                new String[]{"Network", "Adjacent", "Local", "Physical"},
                new String[]{"N", "A", "L", "P"});

        // Scope
        addMetric(metricsPanel, gbc, 1, "Scope", "S",
                new String[]{"Unchanged", "Changed"},
                new String[]{"U", "C"});

        // Attack Complexity
        addMetric(metricsPanel, gbc, 2, "Attack Complexity", "AC",
                new String[]{"Low", "High"},
                new String[]{"L", "H"});

        // Confidentiality
        addMetric(metricsPanel, gbc, 2, "Confidentiality", "C",
                new String[]{"None", "Low", "High"},
                new String[]{"N", "L", "H"});

        // Privileges Required
        addMetric(metricsPanel, gbc, 3, "Privileges Required", "PR",
                new String[]{"None", "Low", "High"},
                new String[]{"N", "L", "H"});


        // Integrity
        addMetric(metricsPanel, gbc, 3, "Integrity", "I",
                new String[]{"None", "Low", "High"},
                new String[]{"N", "L", "H"});


        // User Interaction
        addMetric(metricsPanel, gbc, 4, "User Interaction", "UI",
                new String[]{"None", "Required"},
                new String[]{"N", "R"});


        // Availability
        addMetric(metricsPanel, gbc, 4, "Availability", "A",
                new String[]{"None", "Low", "High"},
                new String[]{"N", "L", "H"});

        add(metricsPanel, BorderLayout.CENTER);
        initializeDefaults();
    }

    private void addMetric(JPanel panel, GridBagConstraints gbc, int y, String label, String abbr, String[] options, String[] values) {
        // Metric Label
        gbc.gridx = (y % 2 != 0) ? 0 : 2; // Column 0 for odd rows, 2 for even
        gbc.gridy = y;
        gbc.anchor = GridBagConstraints.EAST;
        panel.add(new JLabel(label), gbc);

        // Metric Buttons
        gbc.gridx = (y % 2 != 0) ? 1 : 3;
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
        // Simulating default clicks to set initial state
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
                // Manually trigger the action listener logic for initialization
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
                // Update selection map
                String abbr = findAbbrForGroup(group);
                if (abbr != null) {
                    currentSelections.put(abbr, source.getActionCommand());
                }
                // Update colors for all buttons in the group
                for (AbstractButton button : java.util.Collections.list(group.getElements())) {
                    updateButtonColors((JToggleButton) button, button == source);
                }
                updateCvss();
            }
        } else {
             // Prevent deselection, a radio-button like behavior.
            source.setSelected(true);
        }
    }
    
    private void updateButtonColors(JToggleButton button, boolean isSelected) {
        if (isSelected) {
            button.setBackground(new Color(46, 139, 87)); // SeaGreen
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
        if (currentSelections.size() < 8) return; // Ensure all metrics are selected

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
            case "None":
                color = new Color(82, 179, 217); // Light blue
                break;
            case "Low":
                color = new Color(255, 204, 0); // Yellow
                break;
            case "Medium":
                color = new Color(255, 153, 0); // Orange
                break;
            case "High":
                color = new Color(255, 87, 34); // Deep Orange
                break;
            case "Critical":
                color = new Color(205, 0, 0); // Red
                break;
            default:
                color = Color.LIGHT_GRAY;
        }
        baseScoreLabel.setBackground(color);
        baseScoreLabel.setForeground(severity.equals("Low") || severity.equals("Medium") ? Color.BLACK : Color.WHITE);
    }
}

class CvssV31Calculator {

    // Metric values from CVSS v3.1 specification
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
        for (int i = 1; i < parts.length; i++) { // Start from 1 to skip "CVSS:3.1"
            String[] metric = parts[i].split(":");
            metrics.put(metric[0], metric[1]);
        }

        double impactSubScore;
        double exploitabilitySubScore;
        double baseScore;

        String scope = metrics.get("S");
        
        // Impact Sub-Score
        double confidentiality = CIA_MAP.get(metrics.get("C"));
        double integrity = CIA_MAP.get(metrics.get("I"));
        double availability = CIA_MAP.get(metrics.get("A"));

        impactSubScore = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability));

        // Exploitability Sub-Score
        double attackVector = ATTACK_VECTOR_MAP.get(metrics.get("AV"));
        double attackComplexity = ATTACK_COMPLEXITY_MAP.get(metrics.get("AC"));
        double privilegesRequired = PRIVILEGES_REQUIRED_MAP.get(scope).get(metrics.get("PR"));
        double userInteraction = USER_INTERACTION_MAP.get(metrics.get("UI"));
        
        exploitabilitySubScore = 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction;

        if (impactSubScore <= 0) {
            baseScore = 0.0;
        } else {
            if (scope.equals("U")) {
                baseScore = roundup(Math.min(impactSubScore + exploitabilitySubScore, 10));
            } else { // Scope is "C"
                baseScore = roundup(Math.min(1.08 * (impactSubScore + exploitabilitySubScore), 10));
            }
        }
        
        String severity = getSeverity(baseScore);

        return new Score(baseScore, severity);
    }
    
    private static String getSeverity(double score) {
        if (score == 0.0) return "None";
        if (score >= 0.1 && score <= 3.9) return "Low";
        if (score >= 4.0 && score <= 6.9) return "Medium";
        if (score >= 7.0 && score <= 8.9) return "High";
        if (score >= 9.0 && score <= 10.0) return "Critical";
        return "None";
    }
}
