import os
import re
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from sklearn.ensemble import RandomForestClassifier
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'your-secret-key-here'

# MongoDB configuration
MONGO_URI = os.environ.get('MONGO_URI') or "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client["url_safety_analyzer_pro"]
urls_collection = db["urls"]
users_collection = db["users"]
malicious_urls_collection = db["malicious_urls"]
admin_logs_collection = db["admin_logs"]
phishing_patterns_collection = db["phishing_patterns"]
user_activities_collection = db["user_activities"]

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.is_admin = user_data.get('is_admin', False)
        self.created_at = user_data.get('created_at', datetime.now())
        self.last_login = user_data.get('last_login')
        self._is_active = user_data.get('is_active', True)
        self.login_attempts = user_data.get('login_attempts', 0)

    @property
    def is_active(self):
        return self._is_active

@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user_data:
        return None
    return User(user_data)

# Helper Functions
def log_activity(user_id, action, details=None):
    activity_data = {
        "user_id": user_id,
        "action": action,
        "timestamp": datetime.now(),
        "details": details or {},
        "ip_address": request.remote_addr if request else None
    }
    user_activities_collection.insert_one(activity_data)

def normalize_url(url):
    """Normalize URL by adding http:// and www. if missing"""
    if not url:
        return ""
    
    # Remove any existing http:// or https://
    clean_url = re.sub(r'^https?://', '', url.strip())
    
    # Remove www. if present (we'll add it back consistently)
    clean_url = re.sub(r'^www\.', '', clean_url)
    
    # Add www. prefix if it's not an IP address
    if not re.match(r'\d+\.\d+\.\d+\.\d+', clean_url.split('/')[0]):
        clean_url = 'www.' + clean_url
    
    # Add http:// scheme if missing
    if not re.match(r'^https?://', clean_url):
        clean_url = 'http://' + clean_url
    
    return clean_url

# Feature Extraction
def extract_features(url):
    normalized_url = normalize_url(url)
    parsed = urlparse(normalized_url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    phishing_patterns = [p['pattern'] for p in phishing_patterns_collection.find({})]
    
    features = {
        'url_length': len(normalized_url),
        'domain_length': len(domain),
        'path_length': len(path),
        'num_dots': normalized_url.count('.'),
        'num_hyphens': normalized_url.count('-'),
        'num_slash': normalized_url.count('/'),
        'num_question': normalized_url.count('?'),
        'num_equal': normalized_url.count('='),
        'num_at': normalized_url.count('@'),
        'num_amp': normalized_url.count('&'),
        'uses_https': int(parsed.scheme == 'https'),
        'has_ip': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain))),
        'sus_keywords': int(any(re.search(pattern, normalized_url.lower()) for pattern in phishing_patterns)),
        'is_shortened': int(any(x in domain for x in ['bit.ly', 'goo.gl', 'tinyurl.com'])),
        'subdomain_levels': domain.count('.') - 1,  # Subtract 1 for www
        'domain_age_days': np.random.randint(0, 365)
    }
    return features

def add_malicious_url(url, url_type, submitted_by, is_phishing=False):
    try:
        normalized_url = normalize_url(url)
        if malicious_urls_collection.find_one({"url": normalized_url}):
            return False
        
        url_data = {
            "url": normalized_url,
            "type": url_type,
            "is_phishing": is_phishing,
            "features": extract_features(normalized_url),
            "submitted_by": submitted_by,
            "date_added": datetime.now(),
            "verified": True
        }
        malicious_urls_collection.insert_one(url_data)
        return True
    except Exception as e:
        print(f"Error adding malicious URL: {e}")
        return False

def check_url_safety(url):
    try:
        normalized_url = normalize_url(url)
        
        # Check against known malicious URLs
        known_malicious = malicious_urls_collection.find_one({"url": normalized_url})
        if known_malicious:
            return {
                'malicious': True,
                'reason': f"Known {known_malicious['type']} site",
                'phishing': known_malicious.get('is_phishing', False),
                'confidence': 1.0,
                'normalized_url': normalized_url,
                'original_url': url,
                'features': known_malicious.get('features', {})
            }
        
        # Use ML model if not known
        if not os.path.exists('url_classifier.joblib'):
            train_model()
        
        model = joblib.load('url_classifier.joblib')
        features = extract_features(normalized_url)
        features_array = np.array(list(features.values())).reshape(1, -1)
        
        prediction = model.predict(features_array)[0]
        proba = model.predict_proba(features_array)[0]
        
        is_phishing = features['sus_keywords'] or features['is_shortened']
        
        # Log the URL check
        if current_user.is_authenticated:
            urls_collection.insert_one({
                "url": normalized_url,
                "original_url": url,
                "is_malicious": bool(prediction == 1),
                "is_phishing": bool(is_phishing),
                "submitted_by": current_user.username if current_user.is_authenticated else 'anonymous',
                "date_added": datetime.now(),
                "features": features
            })
        
        if prediction == 1:
            return {
                'malicious': True,
                'reason': f"Classified as malicious ({proba[1]:.1%} confidence)",
                'phishing': is_phishing,
                'confidence': float(proba[1]),
                'normalized_url': normalized_url,
                'original_url': url,
                'features': features
            }
        return {
            'malicious': False,
            'reason': f"Classified as safe ({proba[0]:.1%} confidence)",
            'phishing': False,
            'confidence': float(proba[0]),
            'normalized_url': normalized_url,
            'original_url': url,
            'features': features
        }
    except Exception as e:
        print(f"Error checking URL: {e}")
        return {
            'malicious': False,
            'reason': "Error analyzing URL",
            'phishing': False,
            'confidence': 0.0,
            'normalized_url': url,
            'original_url': url,
            'features': {}
        }

def train_model():
    try:
        malicious = list(malicious_urls_collection.find({}, {'_id': 0, 'url': 1, 'type': 1}))
        malicious_df = pd.DataFrame(malicious)
        malicious_df['label'] = 1
        
        safe_urls = generate_safe_urls(len(malicious_df))
        safe_df = pd.DataFrame({'url': safe_urls, 'type': 'safe', 'label': 0})
        
        df = pd.concat([malicious_df, safe_df], ignore_index=True)
        
        # Extract features properly
        features_list = []
        for url in df['url']:
            features = extract_features(url)
            features_list.append(list(features.values()))
        
        X = np.array(features_list)
        y = df['label'].values
        
        model = RandomForestClassifier(n_estimators=150, class_weight='balanced', max_depth=10)
        model.fit(X, y)
        joblib.dump(model, 'url_classifier.joblib')
        
        print("Model trained successfully")
        return True
    except Exception as e:
        print(f"Error training model: {e}")
        return False

def generate_safe_urls(n):
    domains = ['google', 'amazon', 'microsoft', 'github', 'wikipedia', 'reddit']
    tlds = ['com', 'org', 'net', 'io', 'edu', 'gov']
    paths = ['', 'search', 'about', 'contact', 'products', 'blog']
    
    urls = []
    for _ in range(n):
        domain = np.random.choice(domains)
        tld = np.random.choice(tlds)
        path = np.random.choice(paths)
        query = np.random.choice(['', '?q=test', '?ref=home', '?page=1'])
        urls.append(f"https://www.{domain}.{tld}/{path}{query}")
    return urls

# HTML Templates
base_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}URL Safety Analyzer{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #3498db;
            --secondary-color: #2980b9;
            --danger-color: #e74c3c;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --light-color: #ecf0f1;
            --dark-color: #2c3e50;
        }
        
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background-color: var(--dark-color) !important;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .navbar-brand {
            font-weight: 700;
            color: white !important;
        }
        
        .nav-link {
            color: rgba(255,255,255,0.85) !important;
            transition: all 0.3s;
        }
        
        .nav-link:hover {
            color: white !important;
            transform: translateY(-2px);
        }
        
        .card {
            border: none;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: all 0.3s;
            margin-bottom: 20px;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        
        .card-header {
            border-radius: 10px 10px 0 0 !important;
            background-color: var(--primary-color);
            color: white;
            font-weight: 600;
        }
        
        .result-card {
            transition: all 0.3s;
        }
        
        .safe {
            border-left: 5px solid var(--success-color);
        }
        
        .malicious {
            border-left: 5px solid var(--danger-color);
        }
        
        .phishing {
            border-left: 5px solid var(--warning-color);
        }
        
        .activity-log {
            max-height: 300px;
            overflow-y: auto;
            background-color: white;
            border-radius: 8px;
            padding: 15px;
        }
        
        .badge {
            font-weight: 500;
            padding: 5px 10px;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-primary:hover {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(52, 152, 219, 0.25);
        }
        
        .input-group-text {
            background-color: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }
        
        #resultContainer {
            transition: all 0.5s ease;
        }
        
        .accordion-button:not(.collapsed) {
            background-color: rgba(52, 152, 219, 0.1);
            color: var(--dark-color);
        }
        
        .table-responsive {
            border-radius: 8px;
            overflow: hidden;
        }
        
        .table {
            margin-bottom: 0;
        }
        
        .table th {
            background-color: var(--primary-color);
            color: white;
        }
        
        .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(52, 152, 219, 0.05);
        }
        
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #dee2e6;
        }
        
        .loading-spinner {
            display: none;
            width: 2rem;
            height: 2rem;
            border: 0.25em solid currentColor;
            border-right-color: transparent;
            border-radius: 50%;
            animation: .75s linear infinite spinner-border;
            margin: 0 auto;
        }
        
        @keyframes spinner-border {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-lock"></i> URL Safety Analyzer
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <div class="navbar-nav ms-auto">
                    <a class="nav-link" href="/"><i class="bi bi-house"></i> Home</a>
                    {% if current_user.is_authenticated %}
                        {% if current_user.is_admin %}
                            <a class="nav-link" href="/admin"><i class="bi bi-speedometer2"></i> Admin Dashboard</a>
                            <a class="nav-link" href="/admin/users"><i class="bi bi-people"></i> User Management</a>
                        {% endif %}
                        <a class="nav-link" href="/logout"><i class="bi bi-box-arrow-right"></i> Logout</a>
                    {% else %}
                        <a class="nav-link" href="/login"><i class="bi bi-box-arrow-in-right"></i> Login</a>
                        <a class="nav-link" href="/register"><i class="bi bi-person-plus"></i> Register</a>
                    {% endif %}
                </div>
            </div>
        </div>
    </nav>
    <div class="container mt-4">
        {% block content %}{% endblock %}
    </div>
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <div class="container">
            <p class="mb-0">URL Safety Analyzer &copy; 2023 | All Rights Reserved</p>
        </div>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
"""

index_template = """
<div class="row justify-content-center">
    <div class="col-md-8">
        <div class="card shadow">
            <div class="card-header">
                <h4 class="mb-0"><i class="bi bi-shield-check"></i> Check URL Safety</h4>
            </div>
            <div class="card-body">
                <form id="checkForm">
                    <div class="input-group mb-3">
                        <span class="input-group-text"><i class="bi bi-link-45deg"></i></span>
                        <input type="url" class="form-control" id="urlInput" placeholder="Enter URL to analyze (e.g., https://example.com)" required>
                        <button class="btn btn-primary" type="submit" id="analyzeBtn">
                            <span id="btnText">Analyze</span>
                            <div class="loading-spinner" id="loadingSpinner"></div>
                        </button>
                    </div>
                </form>
                <div id="resultContainer" class="mt-4" style="display: none;">
                    <div class="card result-card">
                        <div class="card-body">
                            <h5 id="resultTitle" class="card-title"></h5>
                            <p id="resultText" class="card-text"></p>
                            <div id="detailsAccordion" class="accordion mt-3"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    document.getElementById('checkForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('urlInput').value;
        const analyzeBtn = document.getElementById('analyzeBtn');
        const btnText = document.getElementById('btnText');
        const spinner = document.getElementById('loadingSpinner');
        
        // Show loading state
        btnText.textContent = "Analyzing...";
        spinner.style.display = "inline-block";
        analyzeBtn.disabled = true;
        
        try {
            const response = await fetch('/check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `url=${encodeURIComponent(url)}`
            });
            
            const data = await response.json();
            displayResult(data);
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while analyzing the URL');
        } finally {
            // Reset button state
            btnText.textContent = "Analyze";
            spinner.style.display = "none";
            analyzeBtn.disabled = false;
        }
    });

    function displayResult(data) {
        const container = document.getElementById('resultContainer');
        const title = document.getElementById('resultTitle');
        const text = document.getElementById('resultText');
        const accordion = document.getElementById('detailsAccordion');
        
        container.style.display = 'block';
        
        // Clear previous classes
        const resultCard = container.querySelector('.card');
        resultCard.className = 'card result-card';
        
        if (data.is_malicious) {
            resultCard.classList.add(data.is_phishing ? 'phishing' : 'malicious');
            title.innerHTML = `<i class="bi bi-exclamation-triangle-fill text-danger"></i> Dangerous URL Detected`;
            text.innerHTML = `
                <div class="alert alert-danger">
                    <strong>Warning:</strong> ${data.reason}
                </div>
                <div class="mb-2"><strong>Original URL:</strong> <span class="text-break">${data.original_url}</span></div>
                <div class="mb-2"><strong>Normalized URL:</strong> <span class="text-break">${data.normalized_url}</span></div>
                <div><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</div>
            `;
        } else {
            resultCard.classList.add('safe');
            title.innerHTML = `<i class="bi bi-check-circle-fill text-success"></i> Safe URL`;
            text.innerHTML = `
                <div class="alert alert-success">
                    ${data.reason}
                </div>
                <div class="mb-2"><strong>Original URL:</strong> <span class="text-break">${data.original_url}</span></div>
                <div class="mb-2"><strong>Normalized URL:</strong> <span class="text-break">${data.normalized_url}</span></div>
                <div><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</div>
            `;
        }
        
        accordion.innerHTML = `
            <div class="accordion-item">
                <h2 class="accordion-header">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#detailsCollapse">
                        <i class="bi bi-gear"></i> Technical Details
                    </button>
                </h2>
                <div id="detailsCollapse" class="accordion-collapse collapse">
                    <div class="accordion-body">
                        <pre>${JSON.stringify(data.features, null, 2)}</pre>
                    </div>
                </div>
            </div>
        `;
        
        // Scroll to results
        container.scrollIntoView({ behavior: 'smooth' });
    }
</script>
"""

login_template = """
<div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
        <div class="card shadow">
            <div class="card-header bg-primary text-white text-center">
                <h4><i class="bi bi-box-arrow-in-right"></i> Login</h4>
            </div>
            <div class="card-body">
                {% if error %}
                    <div class="alert alert-danger alert-dismissible fade show">
                        {{ error }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endif %}
                <form method="POST" action="/login">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-person"></i></span>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock"></i></span>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="bi bi-box-arrow-in-right"></i> Login
                    </button>
                </form>
                <div class="mt-3 text-center">
                    <p>Don't have an account? <a href="/register">Register here</a></p>
                </div>
            </div>
        </div>
    </div>
</div>
"""

register_template = """
<div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
        <div class="card shadow">
            <div class="card-header bg-primary text-white text-center">
                <h4><i class="bi bi-person-plus"></i> Register</h4>
            </div>
            <div class="card-body">
                {% if error %}
                    <div class="alert alert-danger alert-dismissible fade show">
                        {{ error }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endif %}
                <form method="POST" action="/register">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-person"></i></span>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">Email</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-envelope"></i></span>
                            <input type="email" class="form-control" id="email" name="email" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock"></i></span>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="bi bi-person-plus"></i> Register
                    </button>
                </form>
                <div class="mt-3 text-center">
                    <p>Already have an account? <a href="/login">Login here</a></p>
                </div>
            </div>
        </div>
    </div>
</div>
"""

admin_template = """
<h2 class="mb-4"><i class="bi bi-speedometer2"></i> Admin Dashboard</h2>

<div class="row mb-4">
    <div class="col-md-4">
        <div class="card text-white bg-primary mb-3">
            <div class="card-body">
                <h5 class="card-title"><i class="bi bi-people"></i> Total Users</h5>
                <p class="card-text display-4">{{ stats.total_users }}</p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card text-white bg-danger mb-3">
            <div class="card-body">
                <h5 class="card-title"><i class="bi bi-exclamation-triangle"></i> Malicious URLs</h5>
                <p class="card-text display-4">{{ stats.total_malicious }}</p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card text-white bg-warning mb-3">
            <div class="card-body">
                <h5 class="card-title"><i class="bi bi-shield-exclamation"></i> Phishing URLs</h5>
                <p class="card-text display-4">{{ stats.total_phishing }}</p>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card mb-4">
            <div class="card-header">
                <h5><i class="bi bi-key"></i> Change Admin Password</h5>
            </div>
            <div class="card-body">
                <form id="changePasswordForm">
                    <div class="mb-3">
                        <label for="currentPassword" class="form-label">Current Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock"></i></span>
                            <input type="password" class="form-control" id="currentPassword" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="newAdminPassword" class="form-label">New Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-key"></i></span>
                            <input type="password" class="form-control" id="newAdminPassword" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="confirmAdminPassword" class="form-label">Confirm New Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-key-fill"></i></span>
                            <input type="password" class="form-control" id="confirmAdminPassword" required>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-check-circle"></i> Change Password
                    </button>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card mb-4">
            <div class="card-header">
                <h5><i class="bi bi-clock-history"></i> Recent Admin Actions</h5>
            </div>
            <div class="card-body activity-log">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th><i class="bi bi-person"></i> Admin</th>
                                <th><i class="bi bi-activity"></i> Action</th>
                                <th><i class="bi bi-calendar"></i> Time</th>
                                <th><i class="bi bi-globe"></i> IP</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for log in stats.recent_logs %}
                            <tr>
                                <td>{{ log.username }}</td>
                                <td>{{ log.action }}</td>
                                <td>{{ log.timestamp.strftime('%Y-%m-%d %H:%M') }}</td>
                                <td>{{ log.ip_address }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h5><i class="bi bi-shield-exclamation"></i> Add Phishing Pattern</h5>
    </div>
    <div class="card-body">
        <form id="patternForm">
            <div class="mb-3">
                <label for="pattern" class="form-label">Regex Pattern</label>
                <div class="input-group">
                    <span class="input-group-text"><i class="bi bi-regex"></i></span>
                    <input type="text" class="form-control" id="pattern" required placeholder="Enter regex pattern">
                </div>
                <small class="text-muted">Example: (login|signin|account)</small>
            </div>
            <div class="mb-3">
                <label for="description" class="form-label">Description</label>
                <div class="input-group">
                    <span class="input-group-text"><i class="bi bi-text-paragraph"></i></span>
                    <input type="text" class="form-control" id="description" placeholder="Enter description">
                </div>
            </div>
            <button type="submit" class="btn btn-primary">
                <i class="bi bi-plus-circle"></i> Add Pattern
            </button>
        </form>
    </div>
</div>

<script>
    document.getElementById('patternForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const pattern = document.getElementById('pattern').value;
        const description = document.getElementById('description').value;
        
        if (!pattern) {
            alert('Please enter a valid regex pattern');
            return;
        }
        
        try {
            const response = await fetch('/admin/add_phishing_pattern', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `pattern=${encodeURIComponent(pattern)}&description=${encodeURIComponent(description)}`
            });
            
            const data = await response.json();
            if (data.status === 'success') {
                alert('Pattern added successfully!');
                document.getElementById('patternForm').reset();
            } else {
                alert('Error: ' + data.message);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while adding the pattern');
        }
    });

    document.getElementById('changePasswordForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const currentPassword = document.getElementById('currentPassword').value;
        const newPassword = document.getElementById('newAdminPassword').value;
        const confirmPassword = document.getElementById('confirmAdminPassword').value;
        
        if (!currentPassword || !newPassword || !confirmPassword) {
            alert('Please fill in all fields');
            return;
        }
        
        if (newPassword !== confirmPassword) {
            alert('New passwords do not match!');
            return;
        }
        
        try {
            const response = await fetch('/admin/change_admin_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `current_password=${encodeURIComponent(currentPassword)}&new_password=${encodeURIComponent(newPassword)}`
            });
            
            const data = await response.json();
            if (data.status === 'success') {
                alert('Password changed successfully!');
                document.getElementById('changePasswordForm').reset();
            } else {
                alert('Error: ' + data.message);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while changing password');
        }
    });
</script>
"""

admin_users_template = """
<h2 class="mb-4"><i class="bi bi-people"></i> User Management</h2>

<div class="card mb-4">
    <div class="card-header">
        <h5><i class="bi bi-list-ul"></i> All Users</h5>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th><i class="bi bi-person"></i> Username</th>
                        <th><i class="bi bi-envelope"></i> Email</th>
                        <th><i class="bi bi-info-circle"></i> Status</th>
                        <th><i class="bi bi-clock"></i> Last Login</th>
                        <th><i class="bi bi-gear"></i> Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td>{{ user.email }}</td>
                        <td>
                            {% if user.get('is_active', True) %}
                                <span class="badge bg-success">Active</span>
                            {% else %}
                                <span class="badge bg-danger">Inactive</span>
                            {% endif %}
                            {% if user.get('is_admin', False) %}
                                <span class="badge bg-primary">Admin</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if user.last_login %}
                                {{ user.last_login.strftime('%Y-%m-%d %H:%M') }}
                            {% else %}
                                Never
                            {% endif %}
                        </td>
                        <td>
                            <a href="/admin/user/{{ user._id }}" class="btn btn-sm btn-info">
                                <i class="bi bi-eye"></i> View
                            </a>
                            <button class="btn btn-sm btn-warning reset-password" data-userid="{{ user._id }}">
                                <i class="bi bi-key"></i> Reset Password
                            </button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Password Reset Modal -->
<div class="modal fade" id="resetPasswordModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="bi bi-key"></i> Reset Password</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="resetPasswordForm">
                    <input type="hidden" id="resetUserId">
                    <div class="mb-3">
                        <label for="newPassword" class="form-label">New Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock"></i></span>
                            <input type="password" class="form-control" id="newPassword" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="confirmPassword" class="form-label">Confirm Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock-fill"></i></span>
                            <input type="password" class="form-control" id="confirmPassword" required>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                    <i class="bi bi-x-circle"></i> Cancel
                </button>
                <button type="button" class="btn btn-primary" id="confirmReset">
                    <i class="bi bi-check-circle"></i> Reset Password
                </button>
            </div>
        </div>
    </div>
</div>

<script>
    document.querySelectorAll('.reset-password').forEach(btn => {
        btn.addEventListener('click', function() {
            const userId = this.getAttribute('data-userid');
            document.getElementById('resetUserId').value = userId;
            const modal = new bootstrap.Modal(document.getElementById('resetPasswordModal'));
            modal.show();
        });
    });

    document.getElementById('confirmReset').addEventListener('click', async function() {
        const userId = document.getElementById('resetUserId').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        
        if (!newPassword || !confirmPassword) {
            alert('Please fill in both password fields');
            return;
        }
        
        if (newPassword !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }
        
        try {
            const response = await fetch('/admin/reset_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `user_id=${userId}&new_password=${encodeURIComponent(newPassword)}`
            });
            
            const data = await response.json();
            if (data.status === 'success') {
                alert('Password reset successfully!');
                window.location.reload();
            } else {
                alert('Error: ' + data.message);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while resetting password');
        }
    });
</script>
"""

admin_user_detail_template = """
<h2 class="mb-4"><i class="bi bi-person"></i> User Details: {{ user.username }}</h2>

<div class="row">
    <div class="col-md-6">
        <div class="card mb-4">
            <div class="card-header">
                <h5><i class="bi bi-info-circle"></i> User Information</h5>
            </div>
            <div class="card-body">
                <p><strong><i class="bi bi-person"></i> Username:</strong> {{ user.username }}</p>
                <p><strong><i class="bi bi-envelope"></i> Email:</strong> {{ user.email }}</p>
                <p><strong><i class="bi bi-calendar"></i> Account Created:</strong> {{ user.created_at.strftime('%Y-%m-%d %H:%M') }}</p>
                <p><strong><i class="bi bi-clock"></i> Last Login:</strong> 
                    {% if user.last_login %}
                        {{ user.last_login.strftime('%Y-%m-%d %H:%M') }}
                    {% else %}
                        Never
                    {% endif %}
                </p>
                <p><strong><i class="bi bi-info-circle"></i> Status:</strong> 
                    {% if user.get('is_active', True) %}
                        <span class="badge bg-success">Active</span>
                    {% else %}
                        <span class="badge bg-danger">Inactive</span>
                    {% endif %}
                    {% if user.get('is_admin', False) %}
                        <span class="badge bg-primary">Admin</span>
                    {% endif %}
                </p>
                <button class="btn btn-warning reset-password" data-userid="{{ user._id }}">
                    <i class="bi bi-key"></i> Reset Password
                </button>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card mb-4">
            <div class="card-header">
                <h5><i class="bi bi-clock-history"></i> Recent Activities</h5>
            </div>
            <div class="card-body activity-log">
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th><i class="bi bi-calendar"></i> Time</th>
                                <th><i class="bi bi-activity"></i> Action</th>
                                <th><i class="bi bi-globe"></i> IP</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for activity in activities %}
                            <tr>
                                <td>{{ activity.timestamp.strftime('%Y-%m-%d %H:%M') }}</td>
                                <td>{{ activity.action }}</td>
                                <td>{{ activity.ip_address }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h5><i class="bi bi-link-45deg"></i> Recently Checked URLs</h5>
    </div>
    <div class="card-body activity-log">
        <div class="table-responsive">
            <table class="table table-sm">
                <thead>
                    <tr>
                        <th><i class="bi bi-link"></i> URL</th>
                        <th><i class="bi bi-calendar"></i> Date</th>
                        <th><i class="bi bi-shield-check"></i> Result</th>
                    </tr>
                </thead>
                <tbody>
                    {% for url in checked_urls %}
                    <tr>
                        <td>{{ url.url }}</td>
                        <td>{{ url.date_added.strftime('%Y-%m-%d %H:%M') }}</td>
                        <td>
                            {% if url.is_malicious %}
                                <span class="badge bg-danger">Malicious</span>
                            {% else %}
                                <span class="badge bg-success">Safe</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Password Reset Modal -->
<div class="modal fade" id="resetPasswordModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="bi bi-key"></i> Reset Password</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="resetPasswordForm">
                    <input type="hidden" id="resetUserId" value="{{ user._id }}">
                    <div class="mb-3">
                        <label for="newPassword" class="form-label">New Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock"></i></span>
                            <input type="password" class="form-control" id="newPassword" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="confirmPassword" class="form-label">Confirm Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock-fill"></i></span>
                            <input type="password" class="form-control" id="confirmPassword" required>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                    <i class="bi bi-x-circle"></i> Cancel
                </button>
                <button type="button" class="btn btn-primary" id="confirmReset">
                    <i class="bi bi-check-circle"></i> Reset Password
                </button>
            </div>
        </div>
    </div>
</div>

<script>
    document.querySelector('.reset-password').addEventListener('click', function() {
        const modal = new bootstrap.Modal(document.getElementById('resetPasswordModal'));
        modal.show();
    });

    document.getElementById('confirmReset').addEventListener('click', async function() {
        const userId = document.getElementById('resetUserId').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        
        if (!newPassword || !confirmPassword) {
            alert('Please fill in both password fields');
            return;
        }
        
        if (newPassword !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }
        
        try {
            const response = await fetch('/admin/reset_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `user_id=${userId}&new_password=${encodeURIComponent(newPassword)}`
            });
            
            const data = await response.json();
            if (data.status === 'success') {
                alert('Password reset successfully!');
                window.location.reload();
            } else {
                alert('Error: ' + data.message);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while resetting password');
        }
    });
</script>
"""

def combine_templates(base, content):
    """Combine base template with content template"""
    return base.replace('{% block content %}{% endblock %}', content)

# Routes
@app.route('/')
def index():
    return render_template_string(combine_templates(base_template, index_template))

@app.route('/check', methods=['POST'])
def check_url():
    url = request.form['url']
    result = check_url_safety(url)
    return jsonify(result)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = users_collection.find_one({"username": username})
        if not user_data:
            error = "Invalid username or password"
        else:
            if user_data.get('login_attempts', 0) >= 5:
                error = "Account locked. Too many failed attempts."
            elif 'password' not in user_data:
                error = "Invalid user account configuration"
            elif check_password_hash(user_data['password'], password):
                user = User(user_data)
                login_user(user)
                
                users_collection.update_one(
                    {"_id": user_data['_id']},
                    {"$set": {
                        "last_login": datetime.now(), 
                        "login_attempts": 0
                    }}
                )
                
                log_activity(str(user_data['_id']), "login", {"ip": request.remote_addr})
                return redirect(url_for('index'))
            else:
                users_collection.update_one(
                    {"_id": user_data['_id']},
                    {"$inc": {"login_attempts": 1}}
                )
                remaining_attempts = 5 - (user_data.get('login_attempts', 0) + 1)
                error = f"Invalid username or password. {remaining_attempts} attempts remaining."
    
    return render_template_string(combine_templates(base_template, login_template), error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if users_collection.find_one({"username": username}):
            error = "Username already exists"
        elif users_collection.find_one({"email": email}):
            error = "Email already registered"
        else:
            user_data = {
                "username": username,
                "email": email,
                "password": generate_password_hash(password),
                "created_at": datetime.now(),
                "is_admin": False,
                "is_active": True,
                "login_attempts": 0
            }
            
            result = users_collection.insert_one(user_data)
            user = User(user_data)
            login_user(user)
            
            log_activity(str(result.inserted_id), "registration", {"ip": request.remote_addr})
            return redirect(url_for('index'))
    
    return render_template_string(combine_templates(base_template, register_template), error=error)

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, "logout", {"ip": request.remote_addr})
    logout_user()
    return redirect(url_for('index'))

# Admin Routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    stats = {
        "total_users": users_collection.count_documents({}),
        "total_malicious": malicious_urls_collection.count_documents({}),
        "total_phishing": malicious_urls_collection.count_documents({"is_phishing": True}),
        "recent_logs": list(admin_logs_collection.find().sort("timestamp", -1).limit(5))
    }
    
    log_activity(current_user.id, "admin_dashboard_access")
    return render_template_string(combine_templates(base_template, admin_template), stats=stats)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    users = list(users_collection.find())
    log_activity(current_user.id, "admin_users_access")
    return render_template_string(combine_templates(base_template, admin_users_template), users=users)

@app.route('/admin/user/<user_id>')
@login_required
def admin_user_detail(user_id):
    if not current_user.is_admin:
        return redirect(url_for('admin_users'))
    
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return redirect(url_for('admin_users'))
        
        activities = list(user_activities_collection.find({"user_id": user_id}).sort("timestamp", -1).limit(10))
        checked_urls = list(urls_collection.find({"submitted_by": user['username']}).sort("date_added", -1).limit(10))
        
        log_activity(current_user.id, "admin_user_view", {"viewed_user": user_id})
        return render_template_string(
            combine_templates(base_template, admin_user_detail_template),
            user=user,
            activities=activities,
            checked_urls=checked_urls
        )
    except:
        return redirect(url_for('admin_users'))

@app.route('/admin/add_phishing_pattern', methods=['POST'])
@login_required
def add_phishing_pattern():
    if not current_user.is_admin:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    pattern = request.form['pattern']
    description = request.form.get('description', '')
    
    try:
        re.compile(pattern)
        
        phishing_patterns_collection.insert_one({
            "pattern": pattern,
            "description": description,
            "added_by": current_user.username,
            "date_added": datetime.now()
        })
        
        log_activity(current_user.id, "add_phishing_pattern", {"pattern": pattern})
        return jsonify({"status": "success"})
    except re.error:
        return jsonify({"status": "error", "message": "Invalid regex pattern"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/reset_password', methods=['POST'])
@login_required
def admin_reset_password():
    if not current_user.is_admin:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    user_id = request.form['user_id']
    new_password = request.form['new_password']
    
    try:
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"password": generate_password_hash(new_password)}}
        )
        
        log_activity(current_user.id, "admin_password_reset", {"target_user": user_id})
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/change_admin_password', methods=['POST'])
@login_required
def change_admin_password():
    if not current_user.is_admin:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    
    user_data = users_collection.find_one({"_id": ObjectId(current_user.id)})
    if not check_password_hash(user_data['password'], current_password):
        return jsonify({"status": "error", "message": "Current password is incorrect"}), 400
    
    try:
        users_collection.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {"password": generate_password_hash(new_password)}}
        )
        
        log_activity(current_user.id, "admin_password_change")
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Emergency Admin Reset Route
@app.route('/reset_admin')
def reset_admin():
    admin_data = {
        "username": "admin",
        "email": "admin@urlanalyzer.com",
        "password": generate_password_hash("Admin@123"),
        "is_admin": True,
        "created_at": datetime.now(),
        "is_active": True,
        "login_attempts": 0
    }
    
    result = users_collection.update_one(
        {"username": "admin"},
        {"$set": admin_data},
        upsert=True
    )
    
    return f"""
    Admin account reset:
    - Username: admin
    - Password: Admin@123
    - Upserted: {result.upserted_id is not None}
    - Modified: {result.modified_count}
    """

# Initialize database with required data
def initialize_database():
    # Ensure admin user exists
    admin_data = {
        "username": "admin",
        "email": "admin@urlanalyzer.com",
        "password": generate_password_hash("Admin@123"),
        "is_admin": True,
        "created_at": datetime.now(),
        "is_active": True,
        "login_attempts": 0
    }
    users_collection.update_one(
        {"username": "admin"},
        {"$setOnInsert": admin_data},
        upsert=True
    )
    print("Admin user ensured - username: admin, password: Admin@123")
    
    # Initialize phishing patterns if empty
    if phishing_patterns_collection.count_documents({}) == 0:
        default_patterns = [
            {"pattern": r"login", "description": "Common phishing target"},
            {"pattern": r"account", "description": "Common phishing target"},
            {"pattern": r"verify", "description": "Common phishing target"},
            {"pattern": r"secure", "description": "Common phishing target"},
            {"pattern": r"update", "description": "Common phishing target"},
            {"pattern": r"bank", "description": "Financial phishing"},
            {"pattern": r"paypal", "description": "Financial phishing"},
            {"pattern": r"amazon", "description": "E-commerce phishing"},
            {"pattern": r"apple", "description": "Tech company phishing"},
            {"pattern": r"microsoft", "description": "Tech company phishing"}
        ]
        phishing_patterns_collection.insert_many(default_patterns)
        print("Added default phishing patterns")
    
    # Initialize malicious URLs if empty
    if malicious_urls_collection.count_documents({}) == 0:
        sample_malicious = [
            {"url": "http://www.fake-paypal-login.com", "type": "phishing", "is_phishing": True},
            {"url": "http://www.steam-account-verify.com", "type": "phishing", "is_phishing": True},
            {"url": "http://www.bad-malware-site.com", "type": "malware", "is_phishing": False},
            {"url": "http://www.fake-bank-login.com", "type": "phishing", "is_phishing": True},
            {"url": "http://www.dangerous-exploit.com", "type": "exploit", "is_phishing": False}
        ]
        for url in sample_malicious:
            add_malicious_url(url['url'], url['type'], "system", url['is_phishing'])
        print("Added sample malicious URLs")

if __name__ == '__main__':
    # Initialize database before starting app
    initialize_database()
    
    # Ensure model is trained
    if not os.path.exists('url_classifier.joblib'):
        print("Training model...")
        train_model()
    
    app.run(debug=True)