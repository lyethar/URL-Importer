# -*- coding: utf-8 -*-

from burp import IBurpExtender, ITab
from javax.swing import JPanel, JButton, JLabel, JTextArea, JScrollPane, JFileChooser, BorderFactory, SwingConstants, Box, JTextPane
from javax.swing.filechooser import FileFilter
from java.awt import BorderLayout, FlowLayout, Font, Color, Dimension
from java.awt.event import ActionListener
from java.net import URL
from java.lang import Thread, Runnable
import time

class BurpExtender(IBurpExtender, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("URL Sitemap Importer")
        self.createUI()
        callbacks.addSuiteTab(self)
        callbacks.printOutput("URL Sitemap Importer extension loaded successfully!")
    
    def createUI(self):
        self._mainPanel = JPanel(BorderLayout())
        self._mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        titleLabel = JLabel("URL Sitemap Importer")
        titleLabel.setFont(Font("Arial", Font.BOLD, 16))
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER)
        
        instructionsPane = JTextPane()
        instructionsPane.setContentType("text/html")
        instructionsPane.setText("""
            <html><body style='font-family: Arial; font-size: 12px; padding: 10px;'>
            <h3>Instructions:</h3>
            <ul>
            <li>Click 'Import URLs' to select a file containing URLs</li>
            <li>Supported formats: One URL per line (txt files)</li>
            <li>URLs should include protocol (http:// or https://)</li>
            <li>The extension will send HTTP requests to populate the sitemap</li>
            <li>Progress and results will be shown in the log below</li>
            </ul>
            <p><strong>Example file format:</strong></p>
            <code>
            https://example.com/<br>
            https://example.com/page1<br>
            https://example.com/api/endpoint<br>
            https://subdomain.example.com/path
            </code>
            </body></html>
        """)
        instructionsPane.setEditable(False)
        instructionsPane.setOpaque(False)
        
        controlPanel = JPanel(FlowLayout())
        
        importButton = JButton("Import URLs")
        importButton.setPreferredSize(Dimension(120, 30))
        importButton.addActionListener(ImportButtonListener(self))
        
        clearLogButton = JButton("Clear Log")
        clearLogButton.setPreferredSize(Dimension(100, 30))
        clearLogButton.addActionListener(ClearLogListener(self))
        
        self._statusLabel = JLabel("Ready to import URLs")
        self._statusLabel.setForeground(Color.BLUE)
        
        controlPanel.add(importButton)
        controlPanel.add(clearLogButton)
        controlPanel.add(Box.createHorizontalStrut(20))
        controlPanel.add(self._statusLabel)
        
        self._logArea = JTextArea(15, 50)
        self._logArea.setEditable(False)
        self._logArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self._logArea.setBackground(Color.BLACK)
        self._logArea.setForeground(Color.GREEN)
        logScrollPane = JScrollPane(self._logArea)
        logScrollPane.setBorder(BorderFactory.createTitledBorder("Import Log"))
        
        topPanel = JPanel(BorderLayout())
        topPanel.add(titleLabel, BorderLayout.NORTH)
        topPanel.add(instructionsPane, BorderLayout.CENTER)
        topPanel.add(controlPanel, BorderLayout.SOUTH)
        
        self._mainPanel.add(topPanel, BorderLayout.NORTH)
        self._mainPanel.add(logScrollPane, BorderLayout.CENTER)
    
    def importURLsFromFile(self, file):
        class ImportTask(Runnable):
            def __init__(self, extender, file):
                self.extender = extender
                self.file = file
            
            def run(self):
                try:
                    self.extender.logMessage("Starting URL import from: " + self.file.getName())
                    self.extender._statusLabel.setText("Importing URLs...")
                    self.extender._statusLabel.setForeground(Color.ORANGE)
                    
                    urls = self.extender.readURLsFromFile(self.file)
                    self.extender.logMessage("Found " + str(len(urls)) + " URLs to import")
                    
                    successCount = 0
                    errorCount = 0
                    
                    for i, urlString in enumerate(urls):
                        urlString = urlString.strip()
                        if not urlString:
                            continue
                        
                        try:
                            self.extender.logMessage("Requesting: " + urlString)
                            url = URL(urlString)
                            request = self.extender._helpers.buildHttpRequest(url)
                            port = url.getPort()
                            if port == -1:
                                port = 443 if url.getProtocol() == "https" else 80
                            
                            httpService = self.extender._helpers.buildHttpService(
                                url.getHost(),
                                port,
                                url.getProtocol() == "https"
                            )
                            
                            requestResponse = self.extender._callbacks.makeHttpRequest(httpService, request)
                            
                            # Analyze response
                            response = requestResponse.getResponse()
                            if response:
                                analyzed = self.extender._helpers.analyzeResponse(response)
                                status = analyzed.getStatusCode()
                                bodyOffset = analyzed.getBodyOffset()
                                bodyLength = len(response) - bodyOffset
                                self.extender.logMessage("Status: " + str(status) + " | Body Length: " + str(bodyLength))
                            else:
                                self.extender.logMessage("No response received for: " + urlString)
                            
                            # Force add to sitemap
                            self.extender._callbacks.addToSiteMap(requestResponse)
                            
                            successCount += 1
                            self.extender.logMessage("[" + str(i + 1) + "/" + str(len(urls)) + "] ✓ Added: " + urlString)
                            Thread.sleep(100)
                            
                        except Exception as ex:
                            errorCount += 1
                            self.extender.logMessage("[" + str(i + 1) + "/" + str(len(urls)) + "] ✗ Error processing: " + urlString + " - " + str(ex))
                    
                    self.extender.logMessage("\n=== Import Complete ===")
                    self.extender.logMessage("Successfully imported: " + str(successCount) + " URLs")
                    self.extender.logMessage("Errors: " + str(errorCount) + " URLs")
                    self.extender.logMessage("Total processed: " + str(len(urls)) + " URLs\n")
                    
                    self.extender._statusLabel.setText("Import completed")
                    self.extender._statusLabel.setForeground(Color.GREEN)
                    
                except Exception as e:
                    self.extender.logMessage("Error during import: " + str(e))
                    self.extender._statusLabel.setText("Import failed")
                    self.extender._statusLabel.setForeground(Color.RED)
        
        thread = Thread(ImportTask(self, file))
        thread.start()
    
    def readURLsFromFile(self, file):
        urls = []
        try:
            with open(file.getAbsolutePath(), 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if not line.startswith('http://') and not line.startswith('https://'):
                            line = 'https://' + line
                        urls.append(line)
        except Exception as e:
            self.logMessage("Error reading file: " + str(e))
        return urls
    
    def logMessage(self, message):
        self._logArea.append(message + "\n")
        self._logArea.setCaretPosition(self._logArea.getDocument().getLength())
    
    def clearLog(self):
        self._logArea.setText("")
    
    def getTabCaption(self):
        return "URL Importer"
    
    def getUiComponent(self):
        return self._mainPanel

class ImportButtonListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        fileChooser = JFileChooser()
        fileChooser.setFileFilter(TextFileFilter())
        result = fileChooser.showOpenDialog(self._extender._mainPanel)
        if result == JFileChooser.APPROVE_OPTION:
            selectedFile = fileChooser.getSelectedFile()
            self._extender.importURLsFromFile(selectedFile)

class ClearLogListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender.clearLog()

class TextFileFilter(FileFilter):
    def accept(self, f):
        return f.isDirectory() or f.getName().lower().endswith('.txt')
    
    def getDescription(self):
        return "Text files (*.txt)"
