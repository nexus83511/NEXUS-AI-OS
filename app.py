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
from datetime import datetime, timedelta

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "nexus_secret_key_123_abc") 

# --- Professional Session Configuration ---
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30) # 30 din tak login rahega
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nexus_users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Models (Updated for Email) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False) # Username ki jagah Email
    username = db.Column(db.String(100), nullable=True) 
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    leads_count = db.relationship('LeadStats', backref='owner', lazy=True)
    lead_memories = db.relationship('LeadMemory', backref='agent', lazy=True)
    chats = db.relationship('ChatMessage', backref='user', lazy=True, cascade="all, delete-orphan")

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False) 
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
    chat_id = request.args.get('chat_id', 'default')
    history = ChatMessage.query.filter_by(user_id=current_user.id).order_by(ChatMessage.timestamp.asc()).all()
    return render_template('index.html', 
                           name=current_user.username or current_user.email, 
                           chat_history=history, 
                           active_session=chat_id,
                           sessions=[])

@app.route('/delete-chat', methods=['POST'])
@login_required
def delete_chat():
    try:
        ChatMessage.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({"success": True, "message": "History Cleared!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/lead-vault')
@login_required
def lead_vault():
    memories = LeadMemory.query.filter_by(user_id=current_user.id).order_by(LeadMemory.last_updated.desc()).all()
    return render_template('vault.html', memories=memories)

# --- PROFESSIONAL AUTH ROUTES ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        email = data.get('email') # Email based
        password = data.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True) # "Remember Me" logic
            session.permanent = True
            return jsonify({"success": True}) if request.is_json else redirect(url_for('home'))
        
        flash('Invalid email or password')
        return jsonify({"success": False, "message": "Invalid credentials"}) if request.is_json else render_template('login.html')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!')
        else:
            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(email=email, username=username, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            
            db.session.add(LeadStats(total_saved=0, user_id=new_user.id))
            db.session.commit()
            
            login_user(new_user, remember=True)
            return redirect(url_for('home'))
            
    return render_template('signup.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Reset link sent to your email (Simulation)')
            # Yahan Flask-Mail ka logic ayega future mein
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- CORE AI AGENT & REST OF CODE (Unchanged) ---
@app.route('/ask-agent', methods=['POST'])
@login_required
def ask_agent():
    # ... [Aapka ask_agent wala sara code jo upar discuss hua tha yahan rahega] ...
    # (Pichle reply wala extraction aur memory logic)
    try:
        data = request.get_json()
        user_query = data.get('message')
        prod_context = data.get('product_context', '')
        kb_context = data.get('kb_context', '')
        session_id = data.get('session_id', 'default')

        existing_mem = LeadMemory.query.filter_by(user_id=current_user.id).order_by(LeadMemory.last_updated.desc()).first()
        lead_context = f"\n[ACTIVE LEAD MEMORY]: Name: {existing_mem.lead_identifier}, Co: {existing_mem.company}, Pain: {existing_mem.pain_points}" if existing_mem else ""

        past_chats = ChatMessage.query.filter_by(user_id=current_user.id).order_by(ChatMessage.timestamp.asc()).all()
        system_content = f"You are Nexus AI. Boss: {current_user.username}. Product: {prod_context}. {lead_context}"
        
        messages = [{"role": "system", "content": system_content}]
        for chat in past_chats: messages.append({"role": chat.role, "content": chat.content})
        messages.append({"role": "user", "content": user_query})

        response = client.chat.completions.create(model="gpt-4o", messages=messages)
        reply = response.choices[0].message.content
        
        db.session.add(ChatMessage(user_id=current_user.id, role="user", content=user_query))
        db.session.add(ChatMessage(user_id=current_user.id, role="assistant", content=reply))

        # Memory Extraction Logic
        extraction_prompt = f"Extract lead from: '{user_query}' into JSON {{'name','company','pain','budget'}}"
        extract_res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": extraction_prompt}], response_format={"type": "json_object"})
        
        try:
            l_data = json.loads(extract_res.choices[0].message.content)
            if l_data.get('name') and l_data.get('name') != "Unknown":
                mem = LeadMemory.query.filter_by(lead_identifier=l_data['name'], user_id=current_user.id).first()
                if not mem:
                    mem = LeadMemory(lead_identifier=l_data['name'], user_id=current_user.id)
                    db.session.add(mem)
                mem.company = l_data.get('company', mem.company)
                mem.pain_points = l_data.get('pain', mem.pain_points)
                mem.budget = l_data.get('budget', mem.budget)
                mem.last_updated = datetime.utcnow()
        except: pass

        db.session.commit()
        return jsonify({"reply": reply, "session_id": session_id})
    except Exception as e: return jsonify({"error": str(e)}), 500

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

@app.route('/save-leads', methods=['POST'])
@login_required
def save_leads():
    try:
        data = request.get_json()
        leads_list = data.get('leads', [])
        stats = LeadStats.query.filter_by(user_id=current_user.id).first()
        if stats:
            stats.total_saved += len(leads_list)
            db.session.commit()
        return jsonify({"message": "Success!"})
    except Exception as e: return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10000)