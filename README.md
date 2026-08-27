# 🔐 AI-Based Phishing URL Detection System

An AI/ML-powered web application that analyzes URLs and predicts whether they are **Phishing** or **Legitimate**.

The system combines **URL-based feature engineering**, **TF-IDF text features**, and **Logistic Regression** to perform phishing URL classification. It also includes URL reachability checking and optional integrations with VirusTotal and Google Safe Browsing.

The application is built with **Python and Flask** and is structured for deployment using **Vercel**.                                           
---

## 🚀 Features

- 🔍 Phishing URL detection using Machine Learning
- 🤖 Logistic Regression classification
- 🧠 Manual URL feature extraction
- 🔤 TF-IDF-based URL text representation       - 📊 Confidence score for predictions
- 🌐 URL normalization and validation
- 🟢 Live / 🔴 Dead URL reachability check
- 🛡️ Optional VirusTotal integration
- 🔎 Optional Google Safe Browsing integration
- 🎨 Flask-based web interface
- ☁️ Vercel deployment support
- 🧪 Unit tests for feature extraction
- 📦 Modular project architecture

---

## 🧠 How It Works

The system processes a URL through multiple stages.

```text
                  ┌──────────────────┐
                  │   User enters    │
                  │       URL        │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ URL Normalization│
                  │   & Validation   │
                  └────────┬─────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │     Feature Extraction   │
              ├──────────────────────────┤
              │ • URL Length             │
              │ • Dot Count              │
              │ • HTTPS                  │
              │ • @ Symbol               │
              │ • Hyphen                 │
              │ • IP Address             │
              │ • Suspicious Keywords    │
              └────────────┬─────────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │    TF-IDF        │
                  │ URL Representation│
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Feature Combining│
                  │ + StandardScaler│
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Logistic         │
                  │ Regression Model │
                  └────────┬─────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │      Final Result        │
              ├──────────────────────────┤
              │ 🟢 Legitimate            │
              │ 🔴 Phishing              │
              │ 📊 Confidence Score      │
              │ 🌐 URL Status            │
              └──────────────────────────┘
