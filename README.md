# 🛡️ PhishGuard AI

> **A professional, AI-powered cybersecurity platform for real-time phishing URL detection and threat analysis.**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green.svg)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Random%20Forest-orange.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

PhishGuard AI analyzes URLs in milliseconds using a trained Random Forest machine learning model. Instead of just saying "Safe" or "Phishing", it provides a comprehensive **Risk Score (0-100)**, detailed **Threat Indicators**, and a breakdown of **Suspicious Patterns** to educate users and protect organizations.

---

## ✨ Features

- **🧠 Smart Threat Analysis**: Analyzes 15 distinct URL features (SSL presence, IP patterns, typosquatting, keywords, suspicious TLDs, and more).
- **📊 Real-time Risk Scoring**: Calculates a dynamic risk score from 0-100 and assigns threat levels (Low, Medium, High, Critical).
- **📋 Downloadable Reports**: Generate and export professional cybersecurity investigation reports for any scanned URL.
- **📚 Threat Library**: Built-in educational dashboard explaining different types of phishing (Spear Phishing, Whaling, Pharming, etc.) and how to spot them.
- **🎨 Modern Dark UI**: Premium, glassmorphism-inspired cybersecurity dashboard with responsive design and smooth animations.

---

## 🛠️ Tech Stack

- **Backend Framework:** Python / Flask
- **Machine Learning:** Scikit-learn (Random Forest Classifier)
- **Data Processing:** Pandas, NumPy
- **Frontend UI:** HTML5, CSS3 (Custom Design System), Vanilla JavaScript

---

## 🚀 How to Run Locally

### 1. Clone the Repository
```bash
git clone https://github.com/gajendratanwar2301/PhishGuard-ai.git
cd PhishGuard-ai
```

### 2. Install Dependencies
Ensure you have Python installed, then install the required libraries:
```bash
pip install flask pandas scikit-learn
```

### 3. Run the Application
```bash
python app.py
```
*The server will start at `http://127.0.0.1:5000`*

---

## 📂 Project Structure

```text
PhishGuard-ai/
│
├── app.py                 # Main Flask application and API routes
├── features.py            # URL feature extraction logic (15 signals)
├── train.py               # ML Model training script
├── predict.py             # Standalone CLI prediction tool
├── data.csv               # Dataset of safe and phishing URLs
├── model.pkl              # Serialized Random Forest model
│
├── static/
│   ├── style.css          # Custom cybersecurity design system
│   └── app.js             # Animations, UI logic, and charts
│
└── templates/
    ├── index.html         # Main scanner and educational landing page
    └── dashboard.html     # Analytics and scan history dashboard
```

---

## 🔒 Security Disclaimer
*This project is for educational purposes and cybersecurity awareness. While the ML model is highly accurate on the provided dataset, never trust a suspicious URL even if flagged as safe by automated tools.*
