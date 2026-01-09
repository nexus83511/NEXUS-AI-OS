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
from datetime import datetime

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
    leads_count = db.relationship('LeadStats', backref='owner', lazy=True)
    lead_memories = db.relationship('LeadMemory', backref='agent', lazy=True)

class LeadStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_saved = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class LeadMemory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_identifier = db.Column(db.String(100), nullable=False) 
    company = db.Column(db.String(100))
    pain_points = db.Column(db.Text)
    budget = db.Column(db.String(100))
    summary = db.Column(db.Text)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# --- Routes ---

@app.route('/')
@login_required
def home():
    return render_template('index.html', name=current_user.username)

@app.route('/lead-vault')
@login_required
def lead_vault():
    memories = LeadMemory.query.filter_by(user_id=current_user.id).order_by(LeadMemory.last_updated.desc()).all()
    return render_template('vault.html', memories=memories)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username, password = data.get('username'), data.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return jsonify({"success": True}) if request.is_json else redirect(url_for('home'))
        return jsonify({"success": False, "message": "Invalid credentials"}) if request.is_json else flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
        else:
            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_pw, is_admin=(username.lower() == 'admin'))
            db.session.add(new_user)
            db.session.commit()
            db.session.add(LeadStats(total_saved=0, user_id=new_user.id))
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin-panel')
@login_required
def admin_panel():
    if not current_user.is_admin: return "Access Denied", 403
    users_data = db.session.query(User, LeadStats).join(LeadStats, User.id == LeadStats.user_id).all()
    return render_template('admin.html', users_data=users_data)

@app.route('/upload-pdf', methods=['POST'])
@login_required
def upload_pdf():
    try:
        if 'file' not in request.files: return jsonify({"error": "No file"}), 400
        file = request.files['file']
        reader = PyPDF2.PdfReader(file)
        extracted_text = "".join([page.extract_text() for page in reader.pages if page.extract_text()])
        return jsonify({"text": extracted_text[:7000]})
    except Exception as e: return jsonify({"error": str(e)}), 500

def search_leads(query):
    api_key = os.getenv("SERPER_API_KEY")
    if not api_key: return None
    url = "https://google.serper.dev/search"
    headers = {'X-API-KEY': api_key, 'Content-Type': 'application/json'}
    try:
        response = requests.post(url, headers=headers, data=json.dumps({"q": query}))
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

        if 'chat_history' not in session: session['chat_history'] = []

        # 1. FETCH MEMORY
        lead_memories = LeadMemory.query.filter_by(user_id=current_user.id).all()
        memory_str = ""
        if lead_memories:
            memory_str = "\nYOUR PREVIOUS LEAD DATABASE:\n"
            for m in lead_memories:
                memory_str += f"- {m.lead_identifier} ({m.company}): {m.summary}\n"

        search_data = ""
        if any(word in user_query.lower() for word in ["find", "search", "leads"]):
            raw_results = search_leads(user_query)
            if raw_results: search_data = f"\n\nSearch: {json.dumps(raw_results)[:1500]}"

        system_prompt = f"""You are Nexus AI, personal assistant to {current_user.username}.
        MEMORY LOGS: {memory_str}
        RULES: 1. You answer all questions about previous leads. 2. Be professional. 3. Boss: {current_user.username}."""
        
        messages = [{"role": "system", "content": system_prompt}]
        for msg in session['chat_history'][-5:]: messages.append(msg)
        messages.append({"role": "user", "content": user_query + search_data})

        response = client.chat.completions.create(model="gpt-4o", messages=messages)
        reply = response.choices[0].message.content
        
        # --- NEW: AUTOMATED CHAT LOGGING ---
        # Ye part har chat ko automated save karega chahay user 'Hello' hi kyun na kahe
        chat_log_id = f"Chat_{datetime.now().strftime('%H:%M:%S')}"
        automated_log = LeadMemory(
            lead_identifier=chat_log_id,
            company="General Interaction",
            summary=f"User: {user_query[:50]}... | AI: {reply[:100]}...",
            user_id=current_user.id
        )
        db.session.add(automated_log)

        # 2. DETAILED EXTRACTION (Only if specific info is found)
        extraction_prompt = f"Extract info from: '{user_query}'. Return JSON ONLY: {{\"name\": \"...\", \"company\": \"...\", \"pain\": \"...\", \"budget\": \"...\"}}. Use 'Unknown' if missing."
        extract_res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": extraction_prompt}])
        ext_text = extract_res.choices[0].message.content
        
        if "{" in ext_text:
            try:
                l_data = json.loads(ext_text)
                l_name = l_data.get('name')
                if l_name and l_name != "Unknown":
                    mem = LeadMemory.query.filter_by(lead_identifier=l_name, user_id=current_user.id).first()
                    if not mem:
                        mem = LeadMemory(lead_identifier=l_name, user_id=current_user.id)
                        db.session.add(mem)
                    mem.company = l_data.get('company', mem.company)
                    mem.pain_points = l_data.get('pain', mem.pain_points)
                    mem.budget = l_data.get('budget', mem.budget)
                    mem.summary = reply[:200]
            except: pass

        db.session.commit() # Save everything to database

        session['chat_history'].append({"role": "user", "content": user_query})
        session['chat_history'].append({"role": "assistant", "content": reply})
        session.modified = True 
        return jsonify({"reply": reply})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/save-leads', methods=['POST'])
@login_required
def save_leads():
    try:
        data = request.get_json()
        leads_list = data.get('leads')
        stats = LeadStats.query.filter_by(user_id=current_user.id).first()
        if stats:
            stats.total_saved += len(leads_list)
            db.session.commit()
        return jsonify({"message": "Success!"})
    except Exception as e: return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10000)