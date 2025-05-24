import burp.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTextArea logArea;
    private JLabel statusLabel;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        // Set extension name
        callbacks.setExtensionName("URL Sitemap Importer");
        
        // Create UI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                createUI();
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
        
        callbacks.printOutput("URL Sitemap Importer extension loaded successfully!");
    }
    
    private void createUI() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Title
        JLabel titleLabel = new JLabel("URL Sitemap Importer");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        
        // Instructions
        JTextPane instructionsPane = new JTextPane();
        instructionsPane.setContentType("text/html");
        instructionsPane.setText(
            "<html><body style='font-family: Arial; font-size: 12px; padding: 10px;'>" +
            "<h3>Instructions:</h3>" +
            "<ul>" +
            "<li>Click 'Import URLs' to select a file containing URLs</li>" +
            "<li>Supported formats: One URL per line (txt files)</li>" +
            "<li>URLs should include protocol (http:// or https://)</li>" +
            "<li>The extension will send HTTP requests to populate the sitemap</li>" +
            "<li>Progress and results will be shown in the log below</li>" +
            "</ul>" +
            "<p><strong>Example file format:</strong></p>" +
            "<code>" +
            "https://example.com/<br>" +
            "https://example.com/page1<br>" +
            "https://example.com/api/endpoint<br>" +
            "https://subdomain.example.com/path" +
            "</code>" +
            "</body></html>"
        );
        instructionsPane.setEditable(false);
        instructionsPane.setOpaque(false);
        
        // Control panel
        JPanel controlPanel = new JPanel(new FlowLayout());
        
        JButton importButton = new JButton("Import URLs");
        importButton.setPreferredSize(new Dimension(120, 30));
        importButton.addActionListener(new ImportButtonListener());
        
        JButton clearLogButton = new JButton("Clear Log");
        clearLogButton.setPreferredSize(new Dimension(100, 30));
        clearLogButton.addActionListener(e -> logArea.setText(""));
        
        statusLabel = new JLabel("Ready to import URLs");
        statusLabel.setForeground(Color.BLUE);
        
        controlPanel.add(importButton);
        controlPanel.add(clearLogButton);
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(statusLabel);
        
        // Log area
        logArea = new JTextArea(15, 50);
        logArea.setEditable(false);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        logArea.setBackground(Color.BLACK);
        logArea.setForeground(Color.GREEN);
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setBorder(BorderFactory.createTitledBorder("Import Log"));
        
        // Layout
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(titleLabel, BorderLayout.NORTH);
        topPanel.add(instructionsPane, BorderLayout.CENTER);
        topPanel.add(controlPanel, BorderLayout.SOUTH);
        
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(logScrollPane, BorderLayout.CENTER);
    }
    
    private class ImportButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
                @Override
                public boolean accept(File f) {
                    return f.isDirectory() || f.getName().toLowerCase().endsWith(".txt");
                }
                
                @Override
                public String getDescription() {
                    return "Text files (*.txt)";
                }
            });
            
            int result = fileChooser.showOpenDialog(mainPanel);
            if (result == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                importURLsFromFile(selectedFile);
            }
        }
    }
    
    private void importURLsFromFile(File file) {
        SwingWorker<Void, String> worker = new SwingWorker<Void, String>() {
            @Override
            protected Void doInBackground() throws Exception {
                publish("Starting URL import from: " + file.getName());
                statusLabel.setText("Importing URLs...");
                statusLabel.setForeground(Color.ORANGE);
                
                List<String> urls = readURLsFromFile(file);
                publish("Found " + urls.size() + " URLs to import");
                
                int successCount = 0;
                int errorCount = 0;
                
                for (int i = 0; i < urls.size(); i++) {
                    String urlString = urls.get(i).trim();
                    if (urlString.isEmpty()) continue;
                    
                    try {
                        URL url = new URL(urlString);
                        
                        // Create HTTP request
                        byte[] request = helpers.buildHttpRequest(url);
                        
                        // Send request through Burp
                        IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(
                            callbacks.getHelpers().buildHttpService(
                                url.getHost(), 
                                url.getPort() == -1 ? (url.getProtocol().equals("https") ? 443 : 80) : url.getPort(), 
                                url.getProtocol().equals("https")
                            ), 
                            request
                        );
                        
                        // Add to sitemap
                        callbacks.addToSiteMap(requestResponse);
                        
                        successCount++;
                        publish("[" + (i + 1) + "/" + urls.size() + "] ✓ Added: " + urlString);
                        
                        // Small delay to avoid overwhelming the target
                        Thread.sleep(100);
                        
                    } catch (MalformedURLException ex) {
                        errorCount++;
                        publish("[" + (i + 1) + "/" + urls.size() + "] ✗ Invalid URL: " + urlString + " - " + ex.getMessage());
                    } catch (Exception ex) {
                        errorCount++;
                        publish("[" + (i + 1) + "/" + urls.size() + "] ✗ Error processing: " + urlString + " - " + ex.getMessage());
                    }
                }
                
                publish("\n=== Import Complete ===");
                publish("Successfully imported: " + successCount + " URLs");
                publish("Errors: " + errorCount + " URLs");
                publish("Total processed: " + urls.size() + " URLs\n");
                
                return null;
            }
            
            @Override
            protected void process(List<String> chunks) {
                for (String message : chunks) {
                    logArea.append(message + "\n");
                    logArea.setCaretPosition(logArea.getDocument().getLength());
                }
            }
            
            @Override
            protected void done() {
                statusLabel.setText("Import completed");
                statusLabel.setForeground(Color.GREEN);
            }
        };
        
        worker.execute();
    }
    
    private List<String> readURLsFromFile(File file) throws IOException {
        List<String> urls = new ArrayList<>();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    // Add protocol if missing
                    if (!line.startsWith("http://") && !line.startsWith("https://")) {
                        line = "https://" + line;
                    }
                    urls.add(line);
                }
            }
        }
        
        return urls;
    }
    
    @Override
    public String getTabCaption() {
        return "URL Importer";
    }
    
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}