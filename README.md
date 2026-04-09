# AI-Based Phishing URL Detection System

A simple machine learning-based web application that detects whether a given URL is **phishing or legitimate**.
This project is implemented in a **single Python file** for simplicity and easy execution.

---

## Features

- URL feature extraction
- Machine learning classification (Logistic Regression)
- Real-time prediction via web interface
- Lightweight and easy to run (single file)

---

##  How It Works

1. User enters a URL
2. System extracts features such as:
   - URL length
   - Number of dots
   - HTTPS usage
   - Presence of special characters (@, -)
   - IP address usage
   - Suspicious keywords (login, verify, bank, etc.)
3. Features are scaled
4. Model predicts:
   - **Phishing**
   - **Legitimate**

---

## Project Type

This is an **all-in-one implementation**, meaning:

- No multiple folders required
- No external dataset files needed
- Everything (data + model + app) is inside one Python file

---

## Requirements

Install dependencies:
pip install -r requirements.txt
After installing requirements you may see:
[Process completed (signal 9) - press Enter]
Then press enter, the terminal closes, then open the terminal again and go back to the repository location

## How to Run

After repository cloning:
1. cd AI-Based-Phishing-URL-Detection-System
2. Run the script: python -m models.train_model
3. Run the script: python -m app.app
4. Open browser:http://127.0.0.1:5000/

---

## Model Details

- Algorithm: Logistic Regression
- Feature Scaling: StandardScaler
- Dataset: Small built-in dataset (for demonstration)

---

## Disclaimer

This project is for **educational purposes only**.
It demonstrates phishing detection concepts and should not be used for real-world security systems without improvements.

---

## Future Improvements

- Use larger real-world datasets
- Improve feature engineering
- Add advanced ML models
- Deploy as browser extension

---

## Author

Cybersecurity mini project implementation for learning and demonstration.
