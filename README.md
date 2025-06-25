# CVSSv3.1-BApp

🎯 A Burp Suite Extension for Visual CVSS v3.1 Scoring  
> Author: [Harith Dilshan (h4rithd)](https://github.com/h4rithd)

---

## 🧩 Overview

**CVSSv3.1-BApp** is a graphical extension for [Burp Suite](https://portswigger.net/burp), designed to calculate and visualize [CVSS v3.1](https://www.first.org/cvss/specification-document) base scores directly within your pentesting workflow.

---

## 🎯 Purpose

During penetration testing and vulnerability assessments, it's common to evaluate risk using the **CVSS v3.1 scoring system**. This tool simplifies that process by:

- Letting you **quickly calculate CVSS scores** using a visual interface
- Providing a **real-time graphical risk meter**
- Auto-generating the **CVSS vector string and base score**
- Allowing you to **take screenshots** and paste them directly into your reports

> ✅ No more manually calculating scores or visiting external calculators — everything is built into Burp Suite!

---

## 🖼️ Screenshots


---

## 🧱 Features

- Visual CVSS metric selection interface
- Dynamic CVSS vector string and score display
- Integrated risk meter (speedometer-style visualization)
- Color-coded severity indicators
- Built-in CVSS v3.1 logic (offline)
- Designed to support pentest reporting

---

## 🔧 Installation

1. **Clone or Download** this repository:

```bash
git clone https://github.com/h4rithd/CVSSv3.1-BApp.git
cd CVSSv3.1-BApp
./gradlew clean jar
```

2. Load into Burp Suite:
- Open Burp > Extender > Extensions
- Click "Add"
- Choose Extension Type: Java
- Select the generated JAR from build/libs/CVSSv3.1-BApp.jar
- Navigate to the "CVSS Calculator" tab in Burp Suite

---

## 🛠️ Development

- Java Swing (UI)
- Java 8+ compatible
- Gradle-based build system
- Uses Burp Extender API
