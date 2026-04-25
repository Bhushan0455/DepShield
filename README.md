# 🛡️ DepShield: Dependency Risk Analyzer

DepShield is a system-level tool designed to analyze and evaluate risks in modern software dependencies. It helps developers understand not just *what is vulnerable*, but *why it matters* and *what to do about it*.

---

## 🚨 Problem

Modern applications depend heavily on open-source packages, but existing tools often fall short:

- They generate **noisy alerts** without context  
- They don’t account for **transitive dependencies**  
- They ignore **maintainer trust and activity**  
- They don’t help developers **prioritize real risk**

👉 As a result, developers struggle to make informed decisions about dependency safety.

---

## 💡 Solution

DepShield approaches dependency analysis as a **system-level problem**, where risk is determined by multiple interacting factors rather than a single vulnerability.

It follows a simple reasoning flow:

> **Observe → Analyze → Evaluate → Recommend**

---

## ⚙️ How It Works

DepShield evaluates dependencies using multiple signals:

### 🔍 Signals Considered

- **🛑 Vulnerability Data (OSV)**  
  Detects known security issues (CVEs)

- **📦 Version Analysis**  
  Flags outdated packages and risky upgrade paths

- **🌐 Dependency Depth**  
  Considers whether a dependency is direct or deeply nested

- **👤 Maintainer Activity**  
  Identifies packages with low activity or potential risk

---

### 🧠 Risk Evaluation

These signals are combined to generate a **context-aware risk assessment**, helping developers:

- Focus on high-impact issues  
- Reduce unnecessary alerts  
- Understand dependency health more clearly  

---

## 📊 Example Output
Dependency: example-lib@1.2.0
Risk: HIGH

Reasons:

Known vulnerability detected
Maintainer inactive
Major version gap

Recommendation:

Upgrade to v2.x (stable)
Review compatibility before moving to v3.x


---

## ✨ Features

- Context-aware dependency risk analysis  
- Support for direct and transitive dependencies  
- Actionable recommendations (not just alerts)  
- Lightweight and fast frontend dashboard  

---

## 🏗️ Tech Stack

- **Frontend**: React + Vite + Tailwind CSS  
- **Backend**: Python (Flask)  
- **Data Sources**: OSV, package metadata  

---

## 🚀 Getting Started

### Prerequisites

- Node.js (v18+)  
- Python (v3.8+)  
- Git  

---

### Installation

```bash
git clone https://github.com/Bhushan0455/DepShield.git
cd DepShield
npm install
pip install -r requirements.txt

Run the Application
🔹 Run Both (Recommended)
npm start
🔹 Run Separately

Frontend:

npm run dev

Backend:

npm run backend
