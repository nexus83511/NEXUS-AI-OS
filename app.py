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
# Secret key ko session management ke liye thoda upgrade kiya
app.secret_key = os.getenv("FLASK_SECRET_KEY", "nexus_secret_key_123_abc") 

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# --- Login Logic ---
MASTER_PASSWORD = "admin786" # Aapka password

@app.route('/')
def home():
    # Agar user login nahi hai toh login page dikhao
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

# --- Email Automation Route ---
@app.route('/send-email', methods=['POST'])
def send_email():
    try:
        data = request.get_json()
        recipient = data.get('email')
        subject = data.get('subject', 'Business Proposal from Nexus AI')
        body = data.get('body')

        # Hum Mailgun ya SendGrid use kar sakte hain, abhi ke liye dummy response
        # Aapko yahan apna email API key lagana hoga
        print(f"Sending Email to {recipient} with body: {body[:50]}...")
        
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

# --- NAYA ROUTE: PDF Upload aur Text Extraction ---
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
            for page_num in range(len(reader.pages)):
                page = reader.pages[page_num]
                extracted_text += page.extract_text()
            
            return jsonify({"text": extracted_text[:7000]})
            
    except Exception as e:
        print(f"PDF Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/ask-agent', methods=['POST'])
def ask_agent():
    try:
        data = request.get_json()
        user_query = data.get('message')
        
        product_context = data.get('product_context', 'Nexus AI-OS Automation Services')
        kb_context = data.get('kb_context', 'No specific company data provided.')

        if 'chat_history' not in session:
            session['chat_history'] = []

        search_data = ""
        if any(word in user_query.lower() for word in ["find", "search", "leads", "business"]):
            raw_results = search_leads(user_query)
            if raw_results:
                search_data = f"\n\nReal-time Search Results: {json.dumps(raw_results)[:2000]}"

        system_prompt = f"""
        You are the Nexus Autonomous Sales & Support Engine. 
        
        MISSION 1 (SALES): Sell this product/service: {product_context}
        MISSION 2 (SUPPORT): Use this 'Company Knowledge Base' for specific business facts: {kb_context}

        OPERATING RULES:
        - If the user asks about pricing, services, or how the company works, refer ONLY to the Knowledge Base.
        - If the user wants to find clients, use the search data to pitch {product_context}.
        - Always provide ROI and be professional.
        - If information is missing from the Knowledge Base, politely say you'll check with the team.
        """
        
        messages = [{"role": "system", "content": system_prompt}]
        for msg in session['chat_history']:
            messages.append(msg)
        
        final_prompt = user_query + (f"\nReal-time Data: {search_data}" if search_data else "")
        messages.append({"role": "user", "content": final_prompt})

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages
        )
        
        reply = response.choices[0].message.content
        session['chat_history'].append({"role": "user", "content": user_query})
        session['chat_history'].append({"role": "assistant", "content": reply})
        session.modified = True 

        return jsonify({"reply": reply})

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/save-leads', methods=['POST'])
def save_leads():
    try:
        data = request.get_json()
        leads_list = data.get('leads')
        if not leads_list:
            return jsonify({"error": "No leads found to save"}), 400

        filename = "nexus_leads.csv"
        keys = leads_list[0].keys()
        with open(filename, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(leads_list)
        return jsonify({"message": f"Success! Leads saved to {filename}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10000)