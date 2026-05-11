from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import joblib
import re
import string
import os
import socket
import logging
from pathlib import Path

from urllib.parse import urlparse
import requests
import datetime
import subprocess
from functools import lru_cache
from dateutil import parser as date_parser
try:
    import whois
except ImportError:
    whois = None

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "toPickleFiles"


# NLTK requirements for email cleaning
import nltk
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
from nltk.stem import PorterStemmer

# Download NLTK data if needed (usually handled but to be safe we can just use the stemmer without downloading if we don't need punkt)
stemmer = PorterStemmer()

def clean_email_text(text):
    text = text.lower()
    text = re.sub(r'\d+', '', text)
    text = text.translate(str.maketrans('', '', string.punctuation))
    words = text.split()
    words = [stemmer.stem(word) for word in words if word not in ENGLISH_STOP_WORDS]
    return " ".join(words)

import numpy as np

def get_top_keywords(transformed, coef, feature_names, top_n=3):
    contributions = transformed.toarray()[0] * coef
    nonzero_indices = contributions.nonzero()[0]
    if len(nonzero_indices) == 0:
        return []
    sorted_indices = nonzero_indices[np.argsort(contributions[nonzero_indices])[::-1]]
    top_indices = sorted_indices[:top_n]
    return [feature_names[i] for i in top_indices if contributions[i] > 0]

def clean_url_text(url):
    url = url.lower()
    url = re.sub(r"http[s]?://", "", url)
    url = re.sub(r"www\.", "", url) 
    return url

def clean_prompt_text(text):
    text = text.lower()
    text = re.sub(r"[^a-z0-9 ]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

@lru_cache(maxsize=100)
def get_ip_and_domain(url):
    domain = url
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = domain.split('/')[0] # handle paths
        ip = socket.gethostbyname(domain)
        return domain, ip
    except Exception:
        return domain, "Unknown"

@lru_cache(maxsize=100)
def fetch_ip_geo(ip):
    default_data = {
        "country": "Unknown", "regionName": "Unknown", "city": "Unknown",
        "zip": "Unknown", "lat": "Unknown", "lon": "Unknown", 
        "timezone": "Unknown", "isp": "Unknown", "org": "Unknown", "as": "Unknown", "raw": {}
    }
    if ip == "Unknown":
        return default_data
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "regionName": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "zip": data.get("zip", "Unknown"),
                    "lat": data.get("lat", "Unknown"),
                    "lon": data.get("lon", "Unknown"),
                    "timezone": data.get("timezone", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "as": data.get("as", "Unknown"),
                    "raw": data
                }
    except Exception:
        pass
    return default_data

@lru_cache(maxsize=100)
def fetch_domain_age(domain):
    try:
        API_KEY = "YOUR_API_KEY"
        if API_KEY != "YOUR_API_KEY":
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={API_KEY}&domainName={domain}&outputFormat=JSON"
            res = requests.get(url, timeout=5).json()
            creation = res.get("WhoisRecord", {}).get("createdDate")
            if creation:
                creation_date = datetime.datetime.fromisoformat(creation.replace("Z", "+00:00"))
                delta = datetime.datetime.now(datetime.timezone.utc) - creation_date.astimezone(datetime.timezone.utc)
                return f"{delta.days} Days"
    except Exception:
        pass
    try:
        if whois is not None:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                return f"{(datetime.datetime.now() - creation).days} Days"
    except Exception:
        pass
    
    # Fallback to subprocess if whois library fails or is missing
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=5)
        output = result.stdout
        match = re.search(r'(?i)(creation date|created on|registered on)[\s]*:[\s]*([^\n\r]+)', output)
        if match:
            date_str = match.group(2).strip()
            try:
                creation_date = date_parser.parse(date_str, fuzzy=True)
                delta = datetime.datetime.now(datetime.timezone.utc) - creation_date.astimezone(datetime.timezone.utc)
                return f"{delta.days} Days"
            except Exception:
                return f"Created: {date_str}"
    except Exception:
        pass
    return "Unknown"

@lru_cache(maxsize=100)
def check_urlhaus(url):
    try:
        data = {'url': url}
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data=data, timeout=3)
        if r.status_code == 200:
            res = r.json()
            if res.get("query_status") == "ok":
                return {
                    "status": "Malicious",
                    "threat": res.get("threat", "unknown"),
                    "tags": res.get("tags", [])
                }
            elif res.get("query_status") == "no_results":
                return {"status": "Not Found", "threat": "None", "tags": []}
    except Exception:
        pass
    return {"status": "Unknown", "threat": "Unknown", "tags": []}

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "wikipedia.org",
    "netflix.com", "whatsapp.com", "openai.com"
}

def extract_domain(url):
    # Fallback parsing in case URL lacks http://
    if not url.startswith('http'):
        url = 'http://' + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def is_whitelisted(url):
    domain = extract_domain(url)
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Third Eye Threat Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_model(path: Path):
    if path.exists():
        return joblib.load(path)
    logger.warning(f"Model file not found: {path}. Predictions requiring this model will fail.")
    return None

# Load Models
# 1. Email
email_vec = load_model(MODEL_DIR / "email_models" / "vectorizer_email.pkl")
email_lr = load_model(MODEL_DIR / "email_models" / "lr_model_email.pkl")
email_feature_names = email_vec.get_feature_names_out() if email_vec else []

# 2. URL
url_vec = load_model(MODEL_DIR / "url_models" / "url_vectorizer.pkl")
url_lr = load_model(MODEL_DIR / "url_models" / "url_lr_model.pkl")
url_le = load_model(MODEL_DIR / "url_models" / "url_label_encoder.pkl")
url_feature_names = url_vec.get_feature_names_out() if url_vec else []

# 3. Prompt
prompt_vec = load_model(MODEL_DIR / "prompt_models" / "prompt_vectorizer.pkl")
prompt_lr = load_model(MODEL_DIR / "prompt_models" / "prompt_lr.pkl")
prompt_feature_names = prompt_vec.get_feature_names_out() if prompt_vec else []

class PredictRequest(BaseModel):
    text: str

@app.post("/predict/email")
def predict_email(req: PredictRequest):
    cleaned = clean_email_text(req.text)
    transformed = email_vec.transform([cleaned])
    prediction = email_lr.predict(transformed)[0]
    
    class_idx = list(email_lr.classes_).index(prediction)
    coef = email_lr.coef_[class_idx]
    keywords = get_top_keywords(transformed, coef, email_feature_names)
    
    if prediction == 'ham':
        result = "Ham"
    else:
        result = "Spam"
        
    return {"prediction": result, "keywords": keywords}

@app.post("/predict/url")
def predict_url(req: PredictRequest):
    cleaned = clean_url_text(req.text)
    transformed = url_vec.transform([cleaned])
    prediction = url_lr.predict(transformed)[0]
    
    class_idx = list(url_lr.classes_).index(prediction)
    coef = url_lr.coef_[class_idx]
    keywords = get_top_keywords(transformed, coef, url_feature_names)
    
    class_name = url_le.inverse_transform([prediction])[0]
    
    # Check Whitelist
    whitelisted = is_whitelisted(req.text)
    
    if class_name == 'benign':
        result = "Safe"
    else:
        # Override ML false positive if domain is trusted
        if whitelisted:
            result = "Safe"
        else:
            result = "Malicious"
        
    # Gather external intelligence
    domain, ip = get_ip_and_domain(req.text)
    geo_data = fetch_ip_geo(ip)
    age = fetch_domain_age(domain)
    urlhaus_data = check_urlhaus(req.text)
    
    threat_text = f"URLHaus: {urlhaus_data['status']}"
    if urlhaus_data['status'] == "Malicious":
        threat_text += f" ({urlhaus_data['threat']})"
    if whitelisted:
        threat_text += " [WHITELISTED]"

    # Risk Analysis Logic
    HIGH_RISK_COUNTRIES = ["RU", "CN", "KP", "IR"]
    CLOUD_ISPS = ["aws", "amazon", "digitalocean", "ovh", "linode", "hetzner", "choopa", "vultr"]
    
    isp_lower = str(geo_data.get('isp', '')).lower()
    country_code = str(geo_data.get('raw', {}).get('countryCode', '')).upper()
    
    is_suspicious_isp = any(cloud in isp_lower for cloud in CLOUD_ISPS) or isp_lower == "unknown"
    is_high_risk_country = country_code in HIGH_RISK_COUNTRIES
    
    if result == "Safe" and not whitelisted:
        if is_suspicious_isp or is_high_risk_country:
            result = "Suspicious"
            
    if result == "Suspicious" and urlhaus_data['status'] == "Malicious":
        result = "Malicious"

    intelligence = {
        "ip": ip,
        "domain_age_days": age,
        "threat_data": threat_text,
        "location_info": {
            "country": geo_data.get("country", "Unknown"),
            "region": geo_data.get("regionName", "Unknown"),
            "city": geo_data.get("city", "Unknown"),
            "zip": geo_data.get("zip", "Unknown"),
            "lat_lon": f"{geo_data.get('lat', 'Unknown')}, {geo_data.get('lon', 'Unknown')}",
            "timezone": geo_data.get("timezone", "Unknown")
        },
        "network_info": {
            "isp": geo_data.get("isp", "Unknown"),
            "org": geo_data.get("org", "Unknown"),
            "asn": geo_data.get("as", "Unknown"),
            "ip": ip
        },
        "raw_json": geo_data.get("raw", {})
    }
        
    return {"prediction": result, "keywords": keywords, "intelligence": intelligence}

@app.post("/predict/prompt")
def predict_prompt(req: PredictRequest):
    cleaned = clean_prompt_text(req.text)
    transformed = prompt_vec.transform([cleaned])
    prediction = prompt_lr.predict(transformed)[0]
    
    if prediction == 1:
        coef = prompt_lr.coef_[0]
    else:
        coef = -prompt_lr.coef_[0]
    keywords = get_top_keywords(transformed, coef, prompt_feature_names)
    
    if prediction == 0:
        result = "Safe"
    else:
        result = "Injection"
        
    return {"prediction": result, "keywords": keywords}

@app.get("/")
def read_root():
    return {"status": "ok", "message": "Third Eye API is running"}

if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment variable for Render deployment, default to 8000 for local
    port = int(os.environ.get("PORT", 8000))
    
    print("\n" + "="*70)
    print("🚀 Project is starting!")
    print(f"🌐 Backend API is running on port {port}")
    print("="*70 + "\n")
    
    # Run uvicorn on 0.0.0.0 to allow external access in deployment
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
