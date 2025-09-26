package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.datatransfer.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import javax.imageio.ImageIO;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

public class BurpExtender implements IBurpExtender, ITab {

    private IBurpExtenderCallbacks callbacks;
    private CvssTab cvssTab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("CVSS v3.1 Visual Calculator");

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

    private final JLabel vectorStringField;
    private final JLabel baseScoreLabel;
    private final Map<String, ButtonGroup> metricGroups = new HashMap<>();
    private final Map<String, String> currentSelections = new HashMap<>();
    private static final String CVSS_VERSION = "CVSS:3.1";
    private int metricRowCounterLeft = 0;
    private int metricRowCounterRight = 0;
    private final RiskMeterPanel riskMeterPanel = new RiskMeterPanel();
    private Color componentBgColor;

    public CvssTab() {
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));
        
        setBackground(UIManager.getColor("Panel.background"));
        componentBgColor = UIManager.getColor("Panel.background");

        // --- Left Column: risk speedometer (top), base score (bottom) ---
        JPanel leftColumn = new JPanel();
        leftColumn.setLayout(new BoxLayout(leftColumn, BoxLayout.Y_AXIS));
        leftColumn.setBackground(componentBgColor);
        leftColumn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Risk Analysis"),
            new EmptyBorder(-12, 8, 8, 8) // Reduced padding
        ));

        // Risk Meter Panel (top of left column)
        riskMeterPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        leftColumn.add(riskMeterPanel);

        leftColumn.add(Box.createVerticalStrut(16)); // spacing between meter and base score

        // Base Score Panel (below risk meter)
        JPanel baseScorePanel = new JPanel();
        baseScorePanel.setLayout(new BoxLayout(baseScorePanel, BoxLayout.Y_AXIS));
        baseScorePanel.setBackground(componentBgColor);
        JLabel baseScoreTitle = new JLabel("Base Score");
        baseScoreTitle.setAlignmentX(Component.CENTER_ALIGNMENT);
        baseScorePanel.add(baseScoreTitle);
        baseScoreLabel = new RoundedLabel("0.0 (None)", 18); // 18 is the arc radius, adjust as needed
        baseScoreLabel.setBackground(UIManager.getColor("Label.background"));
        baseScoreLabel.setForeground(UIManager.getColor("Label.foreground"));
        baseScoreLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        baseScoreLabel.setBorder(new EmptyBorder(8, 18, 8, 18));
        baseScoreLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        baseScorePanel.add(Box.createVerticalStrut(8));
        baseScorePanel.add(baseScoreLabel);

        baseScorePanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        leftColumn.add(baseScorePanel);

        // --- Right Column: vector string (top), button panel (bottom) ---
        JPanel rightColumn = new JPanel();
        rightColumn.setLayout(new BoxLayout(rightColumn, BoxLayout.Y_AXIS));
        rightColumn.setBackground(componentBgColor);
        rightColumn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("CVSS Metrics"),
            new EmptyBorder(8, 8, 8, 8) // Reduced padding
        ));

        // Vector String Panel (top of right column)
        JPanel vectorPanel = new JPanel(new BorderLayout(10, 10));
        vectorStringField = new JLabel("Vector String - CVSS:3.1");
        vectorStringField.setFont(new Font("Monospaced", Font.PLAIN, 14));
        vectorPanel.add(vectorStringField, BorderLayout.CENTER);
        vectorPanel.setMaximumSize(new Dimension(400, 50));
        rightColumn.add(vectorPanel);

        rightColumn.add(Box.createVerticalStrut(16)); // spacing between vector and buttons

        // Metrics panels
        JPanel leftPanel = new JPanel(new GridBagLayout());
        JPanel rightPanel = new JPanel(new GridBagLayout());
        leftPanel.setBackground(componentBgColor);
        rightPanel.setBackground(componentBgColor);

        GridBagConstraints gbcLeft = new GridBagConstraints();
        gbcLeft.fill = GridBagConstraints.HORIZONTAL;
        gbcLeft.insets = new Insets(5, 5, 5, 5);
        gbcLeft.anchor = GridBagConstraints.WEST;

        GridBagConstraints gbcRight = new GridBagConstraints();
        gbcRight.fill = GridBagConstraints.HORIZONTAL;
        gbcRight.insets = new Insets(5, 5, 5, 5);
        gbcRight.anchor = GridBagConstraints.WEST;

        // Left metrics
        addMetric(leftPanel, gbcLeft, metricRowCounterLeft++, "Attack Vector", "AV", new String[]{"Network", "Adjacent", "Local", "Physical"}, new String[]{"N", "A", "L", "P"});
        addMetric(leftPanel, gbcLeft, metricRowCounterLeft++, "Attack Complexity", "AC", new String[]{"Low", "High"}, new String[]{"L", "H"});
        addMetric(leftPanel, gbcLeft, metricRowCounterLeft++, "Privileges Required", "PR", new String[]{"None", "Low", "High"}, new String[]{"N", "L", "H"});
        addMetric(leftPanel, gbcLeft, metricRowCounterLeft++, "User Interaction", "UI", new String[]{"None", "Required"}, new String[]{"N", "R"});

        // Right metrics
        addMetric(rightPanel, gbcRight, metricRowCounterRight++, "Scope", "S", new String[]{"Unchanged", "Changed"}, new String[]{"U", "C"});
        addMetric(rightPanel, gbcRight, metricRowCounterRight++, "Confidentiality", "C", new String[]{"None", "Low", "High"}, new String[]{"N", "L", "H"});
        addMetric(rightPanel, gbcRight, metricRowCounterRight++, "Integrity", "I", new String[]{"None", "Low", "High"}, new String[]{"N", "L", "H"});
        addMetric(rightPanel, gbcRight, metricRowCounterRight++, "Availability", "A", new String[]{"None", "Low", "High"}, new String[]{"N", "L", "H"});

        // Buttons panel (side by side)
        JPanel buttonsPanel = new JPanel(new GridBagLayout());
        buttonsPanel.setBackground(componentBgColor);
        GridBagConstraints metricsGbc = new GridBagConstraints();
        metricsGbc.gridx = 0;
        metricsGbc.gridy = 0;
        metricsGbc.insets = new Insets(0, 0, 0, 20);
        buttonsPanel.add(leftPanel, metricsGbc);
        metricsGbc.gridx = 1;
        buttonsPanel.add(rightPanel, metricsGbc);

        buttonsPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        rightColumn.add(buttonsPanel);

        // --- Main Center Panel: leftColumn | rightColumn ---
        JPanel centerPanel = new JPanel(new GridBagLayout());
        centerPanel.setBackground(componentBgColor);

        GridBagConstraints centerGbc = new GridBagConstraints();
        centerGbc.gridy = 0;
        centerGbc.insets = new Insets(0, 10, 0, 10); // Reduced spacing between panels
        centerGbc.anchor = GridBagConstraints.CENTER;
        centerGbc.fill = GridBagConstraints.NONE;

        // Left side: risk meter + base score
        centerGbc.gridx = 0;
        centerPanel.add(leftColumn, centerGbc);

        // Right side: vector string + button panel
        centerGbc.gridx = 1;
        centerPanel.add(rightColumn, centerGbc);

        // Create a wrapper panel with GridBagLayout for perfect centering
        JPanel mainContentWrapper = new JPanel(new GridBagLayout());
        mainContentWrapper.setBackground(componentBgColor);
        
        // Center constraints
        GridBagConstraints wrapperGbc = new GridBagConstraints();
        wrapperGbc.gridx = 0;
        wrapperGbc.gridy = 0;
        wrapperGbc.weightx = 1.0; // Allow horizontal stretching
        wrapperGbc.weighty = 1.0; // Allow vertical stretching
        wrapperGbc.anchor = GridBagConstraints.CENTER;
        wrapperGbc.fill = GridBagConstraints.NONE;
        
        // Add the center panel to the wrapper with center constraints
        mainContentWrapper.add(centerPanel, wrapperGbc);

        // Add the wrapper to maintain the compact layout
        add(mainContentWrapper, BorderLayout.CENTER);

        // Screenshot buttons panel
        JPanel screenshotPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        screenshotPanel.setBackground(componentBgColor);
        
        JButton saveButton = new JButton("Save as Image");
        saveButton.addActionListener(e -> saveAsImage());
        
        JButton copyButton = new JButton("Copy to Clipboard");
        copyButton.addActionListener(e -> copyToClipboard());
        
        screenshotPanel.add(saveButton);
        screenshotPanel.add(copyButton);
        
        // Footer with buttons and developer info
        JPanel footerPanel = new JPanel();
        footerPanel.setLayout(new BoxLayout(footerPanel, BoxLayout.Y_AXIS));
        footerPanel.setBackground(UIManager.getColor("Panel.background"));
        
        // Add screenshot panel
        screenshotPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        footerPanel.add(screenshotPanel);
        footerPanel.add(Box.createVerticalStrut(10));
        
        // Developer info
        JLabel footerLabel = new JLabel("Developed by Harith Dilshan | h4rithd");
        footerLabel.setFont(new Font("Monospaced", Font.PLAIN, 10));
        footerLabel.setForeground(UIManager.getColor("Label.foreground"));
        footerLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        footerPanel.add(footerLabel);

        add(footerPanel, BorderLayout.SOUTH);

        initializeDefaults();
    }

    private void addMetric(JPanel panel, GridBagConstraints gbc, int row, String label, String abbr, String[] options, String[] values) {
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(new JLabel(label), gbc);

        gbc.gridx = 1;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        buttonPanel.setBackground(componentBgColor);
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
            button.setBackground(UIManager.getColor("Button.select"));
            button.setForeground(UIManager.getColor("Button.selectForeground"));
        } else {
            button.setBackground(UIManager.getColor("Button.background"));
            button.setForeground(UIManager.getColor("Button.foreground"));
        }
    }

    private BufferedImage captureMainPanels() {
        // Find the mainContentWrapper which contains the compact layout
        Component[] components = getComponents();
        JPanel mainWrapper = null;
        for (Component comp : components) {
            if (comp instanceof JPanel && comp.getParent() == this) {
                mainWrapper = (JPanel) comp;
                break;
            }
        }
        
        if (mainWrapper == null) return null;
        
        // Get the actual center panel with the content
        JPanel centerPanel = (JPanel) ((JPanel) mainWrapper.getComponent(0));
        
        // Create a buffered image with minimal padding
        Dimension size = centerPanel.getPreferredSize();
        BufferedImage image = new BufferedImage(
            size.width + 2, // minimal padding
            size.height + 2,
            BufferedImage.TYPE_INT_ARGB
        );
        
        Graphics2D g2d = image.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        
        // Translate to account for minimal padding
        g2d.translate(1, 1);
        
        // Paint with the panel's background
        g2d.setColor(centerPanel.getBackground());
        g2d.fillRect(-1, -1, size.width + 2, size.height + 2);
        
        // Paint the center panel
        centerPanel.paint(g2d);
        g2d.dispose();
        
        return image;
    }

    private void saveAsImage() {
        try {
            BufferedImage image = captureMainPanels();
            if (image == null) {
                JOptionPane.showMessageDialog(this, "Error: Could not capture the panels", 
                    "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("PNG Images", "png"));
            
            if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                String filePath = fileChooser.getSelectedFile().getPath();
                if (!filePath.toLowerCase().endsWith(".png")) {
                    filePath += ".png";
                }
                
                File outputFile = new File(filePath);
                ImageIO.write(image, "png", outputFile);
                JOptionPane.showMessageDialog(this, "Image saved successfully!", 
                    "Success", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Error saving image: " + e.getMessage(), 
                "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void copyToClipboard() {
        try {
            BufferedImage image = captureMainPanels();
            if (image == null) {
                JOptionPane.showMessageDialog(this, "Error: Could not capture the panels", 
                    "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            TransferableImage transferable = new TransferableImage(image);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(transferable, null);
            
            JOptionPane.showMessageDialog(this, "Image copied to clipboard!", 
                "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error copying to clipboard: " + e.getMessage(), 
                "Error", JOptionPane.ERROR_MESSAGE);
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
            case "None": // info
                color = Color.decode("#006fa2");
                break;
            case "Low":
                color = Color.decode("#00c17e");
                break;
            case "Medium":
                color = Color.decode("#ff9655");
                break;
            case "High":
                color = Color.decode("#ff5863");
                break;
            case "Critical":
                color = Color.decode("#de50a6");
                break;
            default:
                color = UIManager.getColor("Label.disabledForeground");
        }
        
        if (color == null) {
            // Fallback colors if UIManager colors are not available
            switch (severity) {
                case "None": // info
                    color = Color.decode("#006fa2");
                    break;
                case "Low":
                    color = Color.decode("#00c17e");
                    break;
                case "Medium":
                    color = Color.decode("#ff9655");
                    break;
                case "High":
                    color = Color.decode("#ff5863");
                    break;
                case "Critical":
                    color = Color.decode("#de50a6");
                    break;
                default:
                    color = Color.LIGHT_GRAY;
            }
        }
        
        baseScoreLabel.setBackground(color);
        baseScoreLabel.setForeground(Color.WHITE);
        riskMeterPanel.setScore(score, severity); // Update risk meter dynamically
    }
}

// --- RiskMeterPanel class ---
class RiskMeterPanel extends JPanel {
    private double score = 0.0;
    private String severity = "None";

    public RiskMeterPanel() {
        setPreferredSize(new Dimension(160, 120));
        setMinimumSize(new Dimension(120, 90));
        setOpaque(false);
    }

    public void setScore(double score, String severity) {
        this.score = score;
        this.severity = severity;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        // Draw speedometer arc
        Graphics2D g2 = (Graphics2D) g.create();
        int w = getWidth();
        int h = getHeight();
        int size = Math.min(w, h) - 20;
        int cx = w / 2;
        int cy = h - 10;
        int radius = size / 2;

        // Draw colored arc segments
        int arcStart = 180;
        int[] arcRanges = {36, 54, 54, 27, 9}; // degrees for None, Low, Medium, High, Critical
        Color[] arcColors = {
            Color.decode("#006fa2"), // None/info
            Color.decode("#00c17e"), // Low
            Color.decode("#ff9655"), // Medium
            Color.decode("#ff5863"), // High
            Color.decode("#de50a6")  // Critical
        };
        int currentStart = arcStart;
        for (int i = 0; i < arcRanges.length; i++) {
            g2.setColor(arcColors[i]);
            g2.setStroke(new BasicStroke(16, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.drawArc(cx - radius, cy - radius, size, size, currentStart, -arcRanges[i]);
            currentStart -= arcRanges[i];
        }

        // Draw needle
        double angle = Math.toRadians(180 - (score / 10.0) * 180);
        int needleLength = radius - 12;
        int nx = (int) (cx + needleLength * Math.cos(angle));
        int ny = (int) (cy - needleLength * Math.sin(angle));
        g2.setColor(Color.DARK_GRAY);
        g2.setStroke(new BasicStroke(3));
        g2.drawLine(cx, cy, nx, ny);

        // Draw center circle
        g2.setColor(Color.WHITE);
        g2.fillOval(cx - 8, cy - 8, 16, 16);
        g2.setColor(Color.GRAY);
        g2.drawOval(cx - 8, cy - 8, 16, 16);

        // Draw score text
        String scoreText = String.format("%.1f", score);
        g2.setFont(new Font("SansSerif", Font.BOLD, 18));
        FontMetrics fm = g2.getFontMetrics();
        int textWidth = fm.stringWidth(scoreText);
        g2.setColor(Color.BLACK);
        g2.drawString(scoreText, cx - textWidth / 2, cy - radius + 35);

        // Draw severity label
        // g2.setFont(new Font("SansSerif", Font.BOLD, 13));
        // String sevText = severity;
        // int sevWidth = g2.getFontMetrics().stringWidth(sevText);
        // g2.setColor(Color.DARK_GRAY);
        // g2.drawString(sevText, cx - sevWidth / 2, cy - radius + 55);

        g2.dispose();
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

    private static double roundUp1Decimal(double value) {
        return Math.ceil(value * 10.0) / 10.0;
    }

    public static Score calculate(String vector) {
        Map<String, String> metrics = new HashMap<>();
        String[] parts = vector.split("/");
        for (int i = 1; i < parts.length; i++) {
            String[] metric = parts[i].split(":");
            metrics.put(metric[0], metric[1]);
        }

        double impactSubScoreBase = 1 - ((1 - CIA_MAP.get(metrics.get("C"))) *
                                        (1 - CIA_MAP.get(metrics.get("I"))) *
                                        (1 - CIA_MAP.get(metrics.get("A"))));

        double impactSubScore = metrics.get("S").equals("U") ?
                6.42 * impactSubScoreBase :
                7.52 * (impactSubScoreBase - 0.029) - 3.25 * Math.pow((impactSubScoreBase - 0.02), 15);

        double exploitabilitySubScore = 8.22 *
                ATTACK_VECTOR_MAP.get(metrics.get("AV")) *
                ATTACK_COMPLEXITY_MAP.get(metrics.get("AC")) *
                PRIVILEGES_REQUIRED_MAP.get(metrics.get("S")).get(metrics.get("PR")) *
                USER_INTERACTION_MAP.get(metrics.get("UI"));

        double baseScore = impactSubScore <= 0 ? 0 :
                (metrics.get("S").equals("U") ?
                        roundUp1Decimal(Math.min(impactSubScore + exploitabilitySubScore, 10)) :
                        roundUp1Decimal(Math.min(1.08 * (impactSubScore + exploitabilitySubScore), 10)));

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

class RoundedLabel extends JLabel {
    private final int arc;

    public RoundedLabel(String text, int arc) {
        super(text);
        this.arc = arc;
        setOpaque(false);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(getBackground());
        g2.fillRoundRect(0, 0, getWidth(), getHeight(), arc, arc);
        super.paintComponent(g);
        g2.dispose();
    }
}

class TransferableImage implements Transferable {
    private Image image;

    public TransferableImage(Image image) {
        this.image = image;
    }

    @Override
    public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
        if (flavor.equals(DataFlavor.imageFlavor)) {
            return image;
        }
        throw new UnsupportedFlavorException(flavor);
    }

    @Override
    public DataFlavor[] getTransferDataFlavors() {
        return new DataFlavor[] { DataFlavor.imageFlavor };
    }

    @Override
    public boolean isDataFlavorSupported(DataFlavor flavor) {
        return flavor.equals(DataFlavor.imageFlavor);
    }
}