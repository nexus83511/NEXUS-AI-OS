import os
import json
import requests
import csv
import PyPDF2  # PDF parhne ke liye
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

app = Flask(__name__)
# Secret key ko session management ke liye
app.secret_key = os.getenv("FLASK_SECRET_KEY", "nexus_secret_key_123_abc") 

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# --- ElevenLabs Settings ---
# Aap apni pasand ki Voice ID yahan badal sakte hain
ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY")
VOICE_ID = "TxGEqn7nUAn3W6E29vgf" # Default: Josh

# --- Login Logic ---
MASTER_PASSWORD = "admin786" # Aapka password

@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if data.get('password') == MASTER_PASSWORD:
        session['logged_in'] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Invalid Password"})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# --- NAYA ROUTE: ElevenLabs Voice AI ---
@app.route('/get-voice', methods=['POST'])
def get_voice():
    try:
        data = request.get_json()
        text = data.get('text')
        
        if not ELEVENLABS_API_KEY:
            return jsonify({"error": "API Key missing"}), 400

        url = f"https://api.elevenlabs.io/v1/text-to-speech/{VOICE_ID}"
        headers = {
            "Accept": "audio/mpeg",
            "Content-Type": "application/json",
            "xi-api-key": ELEVENLABS_API_KEY
        }
        payload = {
            "text": text,
            "model_id": "eleven_monolingual_v1",
            "voice_settings": {"stability": 0.5, "similarity_boost": 0.75}
        }

        response = requests.post(url, json=payload, headers=headers)
        
        if response.status_code == 200:
            return response.content, 200, {'Content-Type': 'audio/mpeg'}
        else:
            return jsonify({"error": "ElevenLabs API Error"}), response.status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Email Automation Route ---
@app.route('/send-email', methods=['POST'])
def send_email():
    try:
        data = request.get_json()
        recipient = data.get('email')
        subject = data.get('subject', 'Business Proposal from Nexus AI')
        body = data.get('body')
        print(f"Sending Email to {recipient}...")
        return jsonify({"message": "Email sent successfully (Simulated)!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Function: Google Search Leads ---
def search_leads(query):
    url = "https://google.serper.dev/search"
    payload = json.dumps({"q": query})
    headers = {
        'X-API-KEY': os.getenv("SERPER_API_KEY"),
        'Content-Type': 'application/json'
    }
    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        return response.json()
    except Exception as e:
        print(f"Search Error: {e}")
        return None

# --- PDF Upload aur Text Extraction ---
@app.route('/upload-pdf', methods=['POST'])
def upload_pdf():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        if file:
            reader = PyPDF2.PdfReader(file)
            extracted_text = ""
            for page in reader.pages:
                extracted_text += page.extract_text()
            return jsonify({"text": extracted_text[:7000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/ask-agent', methods=['POST'])
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
                search_data = f"\n\nSearch: {json.dumps(raw_results)[:2000]}"

        system_prompt = f"You are Nexus AI. Product: {product_context}. Knowledge: {kb_context}."
        
        messages = [{"role": "system", "content": system_prompt}]
        for msg in session['chat_history']:
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
def save_leads():
    try:
        data = request.get_json()
        leads_list = data.get('leads')
        filename = "nexus_leads.csv"
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