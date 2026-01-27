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
                           name=current_user.username, 
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

# --- AUTH ROUTES ---
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

# --- CORE AI AGENT WITH MEMORY ---
@app.route('/ask-agent', methods=['POST'])
@login_required
def ask_agent():
    try:
        data = request.get_json()
        user_query = data.get('message')
        prod_context = data.get('product_context', '')
        kb_context = data.get('kb_context', '')
        session_id = data.get('session_id', 'default')

        # 1. RETRIEVE MEMORY: Last updated lead ki details fetch karna context ke liye
        existing_mem = LeadMemory.query.filter_by(user_id=current_user.id).order_by(LeadMemory.last_updated.desc()).first()
        lead_context = ""
        if existing_mem:
            lead_context = f"\n[ACTIVE LEAD MEMORY]: Current Person: {existing_mem.lead_identifier}, Company: {existing_mem.company}, Pain Points: {existing_mem.pain_points}, Budget: {existing_mem.budget}."

        # 2. FETCH CHAT HISTORY
        past_chats = ChatMessage.query.filter_by(user_id=current_user.id).order_by(ChatMessage.timestamp.asc()).all()
        
        # 3. CONSTRUCT SYSTEM PROMPT
        system_content = (
            f"You are Nexus AI, a professional sales Closer. Boss: {current_user.username}. "
            f"Product: {prod_context}. Knowledge Base: {kb_context}. "
            f"{lead_context} "
            "IMPORTANT: Don't ask for info you already have in [ACTIVE LEAD MEMORY]. "
            "Be conversational, personalized, and empathetic."
        )
        
        messages = [{"role": "system", "content": system_content}]
        for chat in past_chats:
            messages.append({"role": chat.role, "content": chat.content})
        messages.append({"role": "user", "content": user_query})

        # 4. GET AI RESPONSE
        response = client.chat.completions.create(model="gpt-4o", messages=messages)
        reply = response.choices[0].message.content
        
        # Save Interaction to History
        db.session.add(ChatMessage(user_id=current_user.id, role="user", content=user_query))
        db.session.add(ChatMessage(user_id=current_user.id, role="assistant", content=reply))

        # 5. EXTRACTION LOGIC: Background mein details update karna
        extraction_prompt = (
            f"Analyze this message: '{user_query}'. "
            "Extract lead info into JSON only. Use 'Unknown' if not found. "
            "JSON structure: {\"name\": \"...\", \"company\": \"...\", \"pain\": \"...\", \"budget\": \"...\"}"
        )
        
        extract_res = client.chat.completions.create(
            model="gpt-4o-mini", 
            messages=[{"role": "user", "content": extraction_prompt}],
            response_format={ "type": "json_object" }
        )
        
        try:
            l_data = json.loads(extract_res.choices[0].message.content)
            if l_data.get('name') and l_data.get('name') != "Unknown":
                # Check if lead exists, otherwise create
                mem = LeadMemory.query.filter_by(lead_identifier=l_data['name'], user_id=current_user.id).first()
                if not mem:
                    mem = LeadMemory(lead_identifier=l_data['name'], user_id=current_user.id)
                    db.session.add(mem)
                
                # Update fields if AI found new info
                if l_data.get('company') != "Unknown": mem.company = l_data['company']
                if l_data.get('pain') != "Unknown": mem.pain_points = l_data['pain']
                if l_data.get('budget') != "Unknown": mem.budget = l_data['budget']
                mem.summary = reply[:200]
                mem.last_updated = datetime.utcnow()
        except:
            pass

        db.session.commit()
        return jsonify({"reply": reply, "session_id": session_id})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

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