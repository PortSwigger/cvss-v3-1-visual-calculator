# CVSS-v3.1-Visual-Calculator

🎯 A Burp Suite Extension for Visual CVSS v3.1 Scoring  
> Author: [Harith Dilshan (h4rithd)](https://github.com/h4rithd)

---

## 🧩 Overview

**CVSS-v3.1-Visual-Calculator** is a graphical extension for [Burp Suite](https://portswigger.net/burp), designed to calculate and visualize [CVSS v3.1](https://www.first.org/cvss/specification-document) base scores directly within your pentesting workflow.

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

<img width="1348" alt="image" src="https://github.com/user-attachments/assets/9d6ed39b-7bf8-41f2-a90b-0c5bd9d1b85e" />
<img width="1128" alt="image" src="https://github.com/user-attachments/assets/e89b5a84-6bf6-40c5-a1e1-6ac580353d8c" />
<img width="1126" alt="image" src="https://github.com/user-attachments/assets/2cb2ff05-5456-4e8a-94ea-3a19929eb388" />

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
git clone https://github.com/h4rithd/CVSS-v3.1-Visual-Calculator.git
cd CVSS-v3.1-Visual-Calculator
./gradle wrapper
./gradlew clean jar
```

2. Load into Burp Suite:
- Open Burp > Extender > Extensions
- Click "Add"
- Choose Extension Type: Java
- Select the generated JAR from build/libs/CVSS-v3.1-Visual-Calculator.jar
- Navigate to the "CVSS Calculator" tab in Burp Suite

---

## 🛠️ Development

- Java Swing (UI)
- Java 8+ compatible
- Gradle-based build system
- Uses Burp Extender API
