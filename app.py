import os
import json
import requests
import csv
import PyPDF2
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "nexus_secret_key_123_abc") 

# --- Database & Login Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nexus_users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    # Relationship to leads
    leads_count = db.relationship('LeadStats', backref='owner', lazy=True)

class LeadStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_saved = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create Database Tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# OpenAI Client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# --- Authentication Routes ---

@app.route('/')
@login_required
def home():
    return render_template('index.html', name=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if request.is_json:
                return jsonify({"success": True})
            return redirect(url_for('home'))
        
        if request.is_json:
            return jsonify({"success": False, "message": "Invalid credentials"})
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists!')
        else:
            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
            admin_status = True if username.lower() == 'admin' else False
            
            new_user = User(username=username, password=hashed_pw, is_admin=admin_status)
            db.session.add(new_user)
            db.session.commit()
            
            # Initializing lead stats for the new user
            new_stats = LeadStats(total_saved=0, user_id=new_user.id)
            db.session.add(new_stats)
            db.session.commit()
            
            flash('Account created! Please login.')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Admin Panel Route ---
@app.route('/admin-panel')
@login_required
def admin_panel():
    if not current_user.is_admin:
        return "Access Denied: Commanders Only!", 403
    
    # Joining User and LeadStats to get lead counts in one go
    users_data = db.session.query(User, LeadStats).join(LeadStats, User.id == LeadStats.user_id).all()
    return render_template('admin.html', users_data=users_data)

# --- AI & Business Logic Routes (Login Required) ---

@app.route('/upload-pdf', methods=['POST'])
@login_required
def upload_pdf():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        
        reader = PyPDF2.PdfReader(file)
        extracted_text = ""
        for page in reader.pages:
            text = page.extract_text()
            if text: extracted_text += text
        return jsonify({"text": extracted_text[:7000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def search_leads(query):
    api_key = os.getenv("SERPER_API_KEY")
    if not api_key: return None
    url = "https://google.serper.dev/search"
    payload = json.dumps({"q": query})
    headers = {'X-API-KEY': api_key, 'Content-Type': 'application/json'}
    try:
        response = requests.post(url, headers=headers, data=payload)
        return response.json()
    except: return None

@app.route('/ask-agent', methods=['POST'])
@login_required
def ask_agent():
    try:
        data = request.get_json()
        user_query = data.get('message')
        product_context = data.get('product_context', 'Nexus AI-OS')
        kb_context = data.get('kb_context', '')

        if 'chat_history' not in session:
            session['chat_history'] = []

        search_data = ""
        if any(word in user_query.lower() for word in ["find", "search", "leads"]):
            raw_results = search_leads(user_query)
            if raw_results:
                search_data = f"\n\nSearch Results: {json.dumps(raw_results)[:1500]}"

        system_prompt = f"You are Nexus AI, a professional sales engine. User: {current_user.username}. Product: {product_context}. Knowledge: {kb_context}."
        
        messages = [{"role": "system", "content": system_prompt}]
        for msg in session['chat_history'][-5:]:
            messages.append(msg)
        messages.append({"role": "user", "content": user_query + search_data})

        response = client.chat.completions.create(model="gpt-4o", messages=messages)
        reply = response.choices[0].message.content
        
        session['chat_history'].append({"role": "user", "content": user_query})
        session['chat_history'].append({"role": "assistant", "content": reply})
        session.modified = True 

        return jsonify({"reply": reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/save-leads', methods=['POST'])
@login_required
def save_leads():
    try:
        data = request.get_json()
        leads_list = data.get('leads')
        if not leads_list: return jsonify({"error": "No leads"}), 400
        
        # --- Update Lead Stats in Database ---
        stats = LeadStats.query.filter_by(user_id=current_user.id).first()
        if stats:
            stats.total_saved += len(leads_list)
            db.session.commit()
        
        filename = f"leads_{current_user.username}.csv"
        keys = leads_list[0].keys()
        with open(filename, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(leads_list)
        return jsonify({"message": "Success!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10000)