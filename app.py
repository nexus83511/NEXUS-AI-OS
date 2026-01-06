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
    # Relation to lead memories
    lead_memories = db.relationship('LeadMemory', backref='agent', lazy=True)

class LeadStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_saved = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# NEW: Lead Memory Table
class LeadMemory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_identifier = db.Column(db.String(100), nullable=False) # e.g., "Rahul-from-CocaCola"
    company = db.Column(db.String(100))
    pain_points = db.Column(db.Text)
    budget = db.Column(db.String(100))
    summary = db.Column(db.Text)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
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

@app.route('/admin-panel')
@login_required
def admin_panel():
    if not current_user.is_admin:
        return "Access Denied: Commanders Only!", 403
    users_data = db.session.query(User, LeadStats).join(LeadStats, User.id == LeadStats.user_id).all()
    return render_template('admin.html', users_data=users_data)

# --- AI & Business Logic Routes ---

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
        extracted_text = "".join([page.extract_text() for page in reader.pages if page.extract_text()])
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

        # 1. FETCH MEMORY: Kya is user ke paas is lead ki purani baatein hain?
        # Hum lead ka naam query se nikaalne ki koshish karte hain
        lead_memories = LeadMemory.query.filter_by(user_id=current_user.id).all()
        memory_context = ""
        if lead_memories:
            memory_context = "\nYour Memory of previous leads:\n"
            for m in lead_memories:
                memory_context += f"- Lead: {m.lead_identifier}, Company: {m.company}, Pain: {m.pain_points}, Budget: {m.budget}, Last Talk: {m.summary}\n"

        search_data = ""
        if any(word in user_query.lower() for word in ["find", "search", "leads"]):
            raw_results = search_leads(user_query)
            if raw_results:
                search_data = f"\n\nSearch Results: {json.dumps(raw_results)[:1500]}"

        system_prompt = f"""You are Nexus AI. 
        Current User (Agent): {current_user.username}. 
        Product: {product_context}. 
        Knowledge: {kb_context}.
        {memory_context}
        Strict Rule: Never share lead data between different Agents. If User A talks to Rahul, User B should not know about it."""
        
        messages = [{"role": "system", "content": system_prompt}]
        for msg in session['chat_history'][-5:]:
            messages.append(msg)
        messages.append({"role": "user", "content": user_query + search_data})

        response = client.chat.completions.create(model="gpt-4o", messages=messages)
        reply = response.choices[0].message.content
        
        # 2. AUTOMATIC EXTRACTION: Background mein data nikalna
        extraction_prompt = f"Analyze this user message: '{user_query}'. If it contains lead info (Name, Company, Pain, Budget), output ONLY a JSON object. If not, output 'NONE'."
        extract_res = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": extraction_prompt}])
        
        ext_text = extract_res.choices[0].message.content
        if "{" in ext_text:
            try:
                lead_data = json.loads(ext_text)
                name = lead_data.get('Name') or lead_data.get('name')
                if name:
                    # Update or Create Memory
                    mem = LeadMemory.query.filter_by(lead_identifier=name, user_id=current_user.id).first()
                    if not mem:
                        mem = LeadMemory(lead_identifier=name, user_id=current_user.id)
                        db.session.add(mem)
                    
                    mem.company = lead_data.get('Company', mem.company)
                    mem.pain_points = lead_data.get('Pain', mem.pain_points)
                    mem.budget = lead_data.get('Budget', mem.budget)
                    mem.summary = reply[:200] # Save a snippet of the last talk
                    db.session.commit()
            except: pass

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