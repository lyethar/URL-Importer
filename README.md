# URL Sitemap Importer for Burp Suite

**URL Sitemap Importer** is a Jython-based Burp Suite extension that allows you to import a list of URLs from a `.txt` file and automatically populate Burp’s Site Map. This is especially useful for pentesters and bug bounty hunters performing passive or pre-auth recon, or for seeding Burp's scanner with known endpoints.

---

## 🔧 Features

- 📝 Load URLs from a plain text file (one URL per line)
- 🌐 Supports both root and subdirectory paths (e.g. `/index.html`, `/folder/.DS_Store`)
- ⚙️ Automatically sends HTTP/S requests via Burp Suite
- 🧠 Populates Burp's Site Map with discovered responses
- 🔍 Built-in logging of request status codes and body lengths
- ✅ Compatible with Burp Suite Professional and Community Edition

---

## 📸 Installation

> Navigate to Burp Extensions and add the Python based file. 

---

## 📁 Supported Input Format

Text file containing one URL per line:
