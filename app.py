import os
import json
import requests
import csv
import PyPDF2
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "nexus_secret_key_123_abc") 

# OpenAI Client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# --- ElevenLabs Settings ---
# Note: Render ke Environment Variables mein ELEVENLABS_API_KEY lazmi set karein.
# Agar code mein direct dalni hai toh niche wali line use karein:
ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY", "sk_660badb8c49037ae280233ad55df7d8adf6e333c6e6e0d82")
VOICE_ID = "TxGEqn7nUAn3W6E29vgf" # Josh Voice ID

# --- Login Logic ---
MASTER_PASSWORD = "admin786"

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

# --- ElevenLabs Voice AI Route ---
@app.route('/get-voice', methods=['POST'])
def get_voice():
    try:
        data = request.get_json()
        text = data.get('text')
        
        if not text:
            return jsonify({"error": "No text provided"}), 400

        # Debugging ke liye print (Render Logs mein dikhayega)
        print(f"Generating voice for text: {text[:30]}...")

        url = f"https://api.elevenlabs.io/v1/text-to-speech/{VOICE_ID}"
        
        headers = {
            "Accept": "audio/mpeg",
            "Content-Type": "application/json",
            "xi-api-key": ELEVENLABS_API_KEY
        }
        
        payload = {
            "text": text,
            "model_id": "eleven_monolingual_v1",
            "voice_settings": {
                "stability": 0.5, 
                "similarity_boost": 0.75
            }
        }

        response = requests.post(url, json=payload, headers=headers)
        
        if response.status_code == 200:
            print("Voice generation successful!")
            return response.content, 200, {'Content-Type': 'audio/mpeg'}
        else:
            # ElevenLabs ki taraf se error details
            error_info = response.json() if response.content else "Unknown Error"
            print(f"ElevenLabs API Error: {response.status_code} - {error_info}")
            return jsonify({"error": "ElevenLabs API Error", "details": error_info}), response.status_code

    except Exception as e:
        print(f"System Error in /get-voice: {str(e)}")
        return jsonify({"error": str(e)}), 500

# --- PDF Upload aur Text Extraction ---
@app.route('/upload-pdf', methods=['POST'])
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
            if text:
                extracted_text += text
        return jsonify({"text": extracted_text[:7000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Search Leads Function ---
def search_leads(query):
    api_key = os.getenv("SERPER_API_KEY")
    if not api_key:
        return {"error": "Serper API key missing"}
        
    url = "https://google.serper.dev/search"
    payload = json.dumps({"q": query})
    headers = {
        'X-API-KEY': api_key,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(url, headers=headers, data=payload)
        return response.json()
    except Exception as e:
        print(f"Search Error: {e}")
        return None

# --- AI Agent Logic ---
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
                search_data = f"\n\nSearch Results: {json.dumps(raw_results)[:1500]}"

        system_prompt = f"You are Nexus AI, a professional sales engine. Context: {product_context}. Knowledge: {kb_context}."
        
        messages = [{"role": "system", "content": system_prompt}]
        for msg in session['chat_history'][-5:]: # Last 5 messages for memory
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

# --- Save Leads to CSV ---
@app.route('/save-leads', methods=['POST'])
def save_leads():
    try:
        data = request.get_json()
        leads_list = data.get('leads')
        if not leads_list:
            return jsonify({"error": "No leads to save"}), 400
            
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