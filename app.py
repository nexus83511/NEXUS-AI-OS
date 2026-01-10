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
    # ChatGPT Style: User ki kai sessions ho sakti hain
    sessions = db.relationship('ChatSession', backref='user', lazy=True, cascade="all, delete-orphan")

class ChatSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), default="New Conversation")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('ChatMessage', backref='session', lazy=True, cascade="all, delete-orphan")

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_session.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False) # 'user' ya 'assistant'
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

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
    # Sidebar ke liye saari purani sessions
    sessions_list = ChatSession.query.filter_by(user_id=current_user.id).order_by(ChatSession.created_at.desc()).all()
    
    # Check karna ke kaunsi chat khuli hui hai
    active_id = request.args.get('chat_id')
    history = []
    if active_id:
        history = ChatMessage.query.filter_by(session_id=active_id).order_by(ChatMessage.timestamp.asc()).all()
    
    return render_template('index.html', 
                           name=current_user.username, 
                           sessions=sessions_list, 
                           chat_history=history, 
                           active_session=active_id)

@app.route('/new-chat')
@login_required
def new_chat():
    new_s = ChatSession(user_id=current_user.id)
    db.session.add(new_s)
    db.session.commit()
    return redirect(url_for('home', chat_id=new_s.id))

@app.route('/delete-session/<int:id>', methods=['POST'])
@login_required
def delete_session(id):
    sess = ChatSession.query.get_or_404(id)
    if sess.user_id == current_user.id:
        db.session.delete(sess)
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/ask-agent', methods=['POST'])
@login_required
def ask_agent():
    try:
        data = request.get_json()
        user_query = data.get('message')
        s_id = data.get('session_id')

        # Agar session nahi hai to banao
        if not s_id or s_id == "None":
            new_s = ChatSession(user_id=current_user.id, title=user_query[:30] + "...")
            db.session.add(new_s)
            db.session.commit()
            s_id = new_s.id
        else:
            sess = ChatSession.query.get(s_id)
            if sess and sess.title == "New Conversation":
                sess.title = user_query[:30] + "..."
                db.session.commit()

        # History fetch karna context ke liye
        past_msgs = ChatMessage.query.filter_by(session_id=s_id).order_by(ChatMessage.timestamp.asc()).all()
        messages = [{"role": "system", "content": f"You are Nexus AI-OS. Boss: {current_user.username}."}]
        for m in past_msgs:
            messages.append({"role": m.role, "content": m.content})
        messages.append({"role": "user", "content": user_query})

        response = client.chat.completions.create(model="gpt-4o", messages=messages)
        reply = response.choices[0].message.content
        
        # Save messages
        db.session.add(ChatMessage(session_id=s_id, role="user", content=user_query))
        db.session.add(ChatMessage(session_id=s_id, role="assistant", content=reply))

        # --- Lead Extraction Logic (Same as yours) ---
        extraction_prompt = f"Extract info: '{user_query}'. JSON ONLY: {{\"name\": \"...\", \"company\": \"...\", \"pain\": \"...\", \"budget\": \"...\"}}."
        extract_res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": extraction_prompt}])
        try:
            l_data = json.loads(extract_res.choices[0].message.content)
            if l_data.get('name') and l_data.get('name') != "Unknown":
                mem = LeadMemory.query.filter_by(lead_identifier=l_data['name'], user_id=current_user.id).first()
                if not mem:
                    mem = LeadMemory(lead_identifier=l_data['name'], user_id=current_user.id)
                    db.session.add(mem)
                mem.company, mem.pain_points, mem.budget = l_data.get('company'), l_data.get('pain'), l_data.get('budget')
                mem.summary = reply[:200]
        except: pass

        db.session.commit()
        return jsonify({"reply": reply, "session_id": s_id})
    except Exception as e: return jsonify({"error": str(e)}), 500

# --- Baaki saare purane routes bilkul waise hi hain ---
@app.route('/lead-vault')
@login_required
def lead_vault_route():
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