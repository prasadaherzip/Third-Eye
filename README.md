# Third Eye - Threat Detection System

A comprehensive, full-stack machine learning application designed for real-time cybersecurity threat analysis. Third Eye provides a centralized interface for detecting malicious URLs, identifying spam/phishing emails, and catching AI prompt injection attacks.

## Features

- **URL Analysis**: Scans URLs and provides real-time intelligence including IP Geolocation, Domain Age, and URLhaus threat status.
- **Deep Network Intelligence**: Extended integration with IP-API to fetch detailed Location Information (Coordinates, Region) and Network Details (ASN, Organization, ISP).
- **Dynamic Risk Logic**: Automatically flags suspicious URLs originating from untrusted cloud hosting providers (e.g. AWS, DigitalOcean) or high-risk countries.
- **Email Filtering**: Classifies email content as Spam or Ham using Natural Language Processing (NLP) and highlights suspicious keywords.
- **Prompt Injection Detection**: Analyzes text inputs to detect adversarial prompts meant to bypass AI safety guardrails.
- **Sleek Cyberpunk UI**: A dynamic, dark-themed frontend ("Nullmask Edition") with neon glow badges, raw JSON toggles, and CSV export capabilities for session history.
- **FastAPI Backend**: A highly performant and robust Python backend to handle machine learning inference and external API requests seamlessly.

## Technology Stack

**Frontend:**
- HTML5 / CSS3 (Vanilla)
- JavaScript (Fetch API for asynchronous requests)
- Custom animations and responsive grid layouts

**Backend:**
- Python 3.x
- FastAPI
- Uvicorn
- Scikit-Learn / Joblib (Machine Learning)
- NLTK (Natural Language Toolkit)
- Requests (External Threat Intelligence APIs)

## Project Structure

```text
Third_Eye_V2/
│
├── Website/
│   ├── Backend/
│   │   └── main.py              # Main FastAPI application and API routes
│   │
│   └── Frontend/
│       ├── index.html           # Main dashboard interface
│       ├── styles.css           # Custom styling and animations
│       └── script.js            # Client-side logic and API integration
│
├── toPickleFiles/               # Pre-trained ML models (.pkl)
│   ├── email_models/
│   ├── url_models/
│   └── prompt_models/
│
├── Datasets/                    # Raw and processed datasets used for training
└── Notebooks/                   # Jupyter notebooks for model training/clustering
```

## Setup & Installation

### 1. Prerequisites
Ensure you have Python 3 installed. You will also need to install the required Python packages.

```bash
pip install fastapi uvicorn scikit-learn pydantic joblib nltk requests python-whois python-dateutil
```

### 2. Running the Application

1. Open a terminal and navigate to the backend directory:
   ```bash
   cd Website/Backend
   ```
2. Start the FastAPI server:
   ```bash
   python main.py
   ```
3. Look at your terminal output! You will see a clickable link (e.g., `http://127.0.0.1:8000`). Click that link to open the frontend interface directly in your browser.

## 🧠 Machine Learning Models

- **URL Model**: Trained on benign and malicious URLs, utilizing TF-IDF vectorization and Logistic Regression.
- **Email Model**: Trained on large datasets of spam and ham emails, utilizing text stemming (NLTK) and Logistic Regression.
- **Prompt Model**: Detects prompt injection techniques by analyzing syntactical patterns common in adversarial prompts.

## 🛡️ Third-Party Intelligence Integration

The URL scanning module actively fetches live data to enhance its prediction confidence:
- **IP-API**: For deep IP profiling, ASN lookups, and geolocation.
- **Whois**: For determining domain age and registration details.
- **URLHaus API**: For checking the URL against known malware distribution sites.

---
*Created as part of an Advanced Machine Learning & Cybersecurity project.*
