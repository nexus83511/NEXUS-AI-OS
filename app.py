import os
import json
import requests
import csv
from flask import Flask, request, jsonify, render_template, session
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

app = Flask(__name__)
app.secret_key = "nexus_secret_key_123_abc" 

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/ask-agent', methods=['POST'])
def ask_agent():
    try:
        data = request.get_json()
        user_query = data.get('message')
        # Frontend se product information pakarna
        product_context = data.get('product_context', 'Nexus AI-OS Automation Services')

        if 'chat_history' not in session:
            session['chat_history'] = []

        search_data = ""
        if any(word in user_query.lower() for word in ["find", "search", "leads", "business"]):
            raw_results = search_leads(user_query)
            if raw_results:
                search_data = f"\n\nReal-time Search Results: {json.dumps(raw_results)[:2000]}"

        # --- ADVANCED POWER PROMPT ---
        # Is mein WhatsApp, Support AI aur Booking ki logic add kardi hai
        system_prompt = f"""
        You are the Nexus Autonomous Sales Engine. 
        Your CURRENT MISSION is to sell these core services: {product_context}
        
        Our specialized solutions include:
        1. WhatsApp AI Bots (Automated customer chat)
        2. Customer Support AI (24/7 smart response)
        3. Appointment Booking AI (Automated scheduling)
        4. Lead Generation AI (Automating the hunt for clients)

        When you find businesses:
        - List their Name, Website, and a 'Pain Point' analysis.
        - Solution: Explain how our {product_context} (specifically AI Bots or Booking) fixes their problem.
        - ROI: Tell them how much time or manual labor they save.
        
        If the user asks for a WhatsApp message or Email, draft a 'High-Converting Pitch'. 
        Be professional, sharp, and results-oriented.
        """
        
        messages = [{"role": "system", "content": system_prompt}]
        for msg in session['chat_history']:
            messages.append(msg)
        
        final_prompt = user_query + (f"\nUse this real-time data to analyze and pitch: {search_data}" if search_data else "")
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