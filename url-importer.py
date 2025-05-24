# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab
from javax.swing import JPanel, JButton, JLabel, JTextArea, JScrollPane, JFileChooser, BorderFactory, SwingConstants, Box, JTextPane
from javax.swing.filechooser import FileFilter
from java.awt import BorderLayout, FlowLayout, Font, Color, Dimension
from java.awt.event import ActionListener
from java.net import URL
from java.lang import Thread, Runnable

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
            <li>Or paste URLs directly below and click 'Submit Pasted URLs'</li>
            <li>Supported format: One URL per line with http(s)</li>
            </ul>
            </body></html>
        """)
        instructionsPane.setEditable(False)
        instructionsPane.setOpaque(False)

        self._pastedURLs = JTextArea(6, 50)
        self._pastedURLs.setFont(Font("Consolas", Font.PLAIN, 12))
        self._pastedURLs.setLineWrap(True)
        self._pastedURLs.setWrapStyleWord(True)
        pasteScroll = JScrollPane(self._pastedURLs)
        pasteScroll.setBorder(BorderFactory.createTitledBorder("Paste URLs (one per line)"))

        controlPanel = JPanel(FlowLayout())
        importButton = JButton("Import URLs")
        importButton.setPreferredSize(Dimension(120, 30))
        importButton.addActionListener(ImportButtonListener(self))

        pasteButton = JButton("Submit Pasted URLs")
        pasteButton.setPreferredSize(Dimension(160, 30))
        pasteButton.addActionListener(PasteURLListener(self))

        clearLogButton = JButton("Clear Log")
        clearLogButton.setPreferredSize(Dimension(100, 30))
        clearLogButton.addActionListener(ClearLogListener(self))

        self._statusLabel = JLabel("Ready to import URLs")
        self._statusLabel.setForeground(Color.BLUE)

        controlPanel.add(importButton)
        controlPanel.add(pasteButton)
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
        topPanel.add(pasteScroll, BorderLayout.SOUTH)

        self._mainPanel.add(topPanel, BorderLayout.NORTH)
        self._mainPanel.add(controlPanel, BorderLayout.CENTER)
        self._mainPanel.add(logScrollPane, BorderLayout.SOUTH)

    def importURLs(self, urls):
        class ImportTask(Runnable):
            def __init__(self, extender, urls):
                self.extender = extender
                self.urls = urls

            def run(self):
                try:
                    self.extender._statusLabel.setText("Importing URLs...")
                    self.extender._statusLabel.setForeground(Color.ORANGE)
                    self.extender.logMessage("Found " + str(len(self.urls)) + " URLs to import")

                    successCount = 0
                    errorCount = 0

                    for i, urlString in enumerate(self.urls):
                        urlString = urlString.strip()
                        if not urlString:
                            continue
                        try:
                            if not urlString.startswith("http"):
                                urlString = "https://" + urlString
                            self.extender.logMessage("Requesting: " + urlString)
                            url = URL(urlString)
                            request = self.extender._helpers.buildHttpRequest(url)
                            port = url.getPort()
                            if port == -1:
                                port = 443 if url.getProtocol() == "https" else 80

                            httpService = self.extender._helpers.buildHttpService(
                                url.getHost(), port, url.getProtocol() == "https"
                            )
                            requestResponse = self.extender._callbacks.makeHttpRequest(httpService, request)

                            response = requestResponse.getResponse()
                            if response:
                                analyzed = self.extender._helpers.analyzeResponse(response)
                                status = analyzed.getStatusCode()
                                self.extender.logMessage("Status: " + str(status))
                            else:
                                self.extender.logMessage("No response for: " + urlString)

                            self.extender._callbacks.addToSiteMap(requestResponse)
                            successCount += 1
                            self.extender.logMessage("[" + str(i + 1) + "/" + str(len(self.urls)) + "] ✓ Added")
                            Thread.sleep(100)

                        except Exception as ex:
                            errorCount += 1
                            self.extender.logMessage("[" + str(i + 1) + "/" + str(len(self.urls)) + "] ✗ Error: " + str(ex))

                    self.extender.logMessage("=== Import Complete ===")
                    self.extender.logMessage("Imported: " + str(successCount) + " | Errors: " + str(errorCount))
                    self.extender._statusLabel.setText("Import completed")
                    self.extender._statusLabel.setForeground(Color.GREEN)

                except Exception as e:
                    self.extender.logMessage("Import failed: " + str(e))
                    self.extender._statusLabel.setText("Import failed")
                    self.extender._statusLabel.setForeground(Color.RED)

        thread = Thread(ImportTask(self, urls))
        thread.start()

    def importURLsFromFile(self, file):
        urls = self.readURLsFromFile(file)
        self.importURLs(urls)

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

class PasteURLListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        pasted = self._extender._pastedURLs.getText()
        urls = [line.strip() for line in pasted.splitlines() if line.strip()]
        if urls:
            self._extender.importURLs(urls)
        else:
            self._extender.logMessage("No pasted URLs provided.")

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
