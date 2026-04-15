# 🛡️ DepShield: AI-Powered Dependency Risk Analyzer

DepShield is a system-level dependency analysis tool designed to identify, evaluate, and explain risks in modern software supply chains.

Unlike traditional tools that only flag known vulnerabilities, DepShield focuses on **context-aware risk reasoning**, helping developers understand *why a dependency is risky*, *how it impacts the system*, and *what action to take*.

---

## 🚨 Problem Statement

Modern applications rely heavily on open-source dependencies, but:

- Vulnerabilities (CVEs) are often flagged **without context**
- Tools like Dependabot generate **noisy alerts**
- Developers lack visibility into **transitive dependency risk**
- No clear way to evaluate **maintainer trust or ecosystem stability**

👉 As a result, teams struggle to prioritize what actually matters.

---

## 💡 Solution: DepShield

DepShield models dependency risk as a **system-level problem**, where risk emerges from multiple interacting signals rather than isolated vulnerabilities.

It follows a structured reasoning approach:

> **Observe → Analyze → Predict → Recommend**

---

## ⚙️ How It Works

DepShield analyzes dependencies using a multi-signal risk model:

### 🔍 Signals Used

- **🛑 Vulnerability Data (OSV)**  
  Detects known CVEs and security issues

- **📦 Version Analysis**  
  Identifies outdated dependencies and risky upgrade paths

- **🌐 Dependency Depth**  
  Evaluates impact based on position in the dependency graph  
  *(direct vs transitive risk)*

- **👤 Maintainer Activity**  
  Flags packages with low activity or potential supply-chain risk

---

### 🧠 Risk Reasoning

These signals are combined to generate a **context-aware risk score**, enabling:

- Better prioritization of fixes
- Reduced alert noise
- System-level understanding of risk propagation

---

## 📊 Example Insight
Dependency: xyz-package@1.2.0
Risk: HIGH

Reasons:

Known vulnerability (CVE detected)
Maintainer inactive for 2+ years
Major version gap (v3 available)

Recommendation:

Upgrade to v2.x (safe)
Avoid v3.x (breaking changes)


---

## 🧩 Key Features

- ✅ AI-driven risk analysis (rule-based currently, extensible to ML/LLMs)
- ✅ Dependency graph awareness (direct + transitive)
- ✅ Context-aware recommendations (not just alerts)
- ✅ Lightweight dashboard (React + Vite)

---

## 🏗️ Tech Stack

- **Frontend**: React + Vite + Tailwind CSS  
- **Backend**: Python (Flask)  
- **Data Sources**: OSV (Open Source Vulnerabilities), package metadata  

---

## 🔮 Future Direction

DepShield explores how software ecosystems can be treated as **complex systems**, similar to industrial assets.

Potential future extensions include:

- 📈 Dependency evolution modeling (time-series risk prediction)
- 🔗 Failure propagation across dependency graphs
- 🤖 LLM-based reasoning for contextual explanations
- 🧪 Benchmarking system-level risk (inspired by frameworks like AssetOpsBench)

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
