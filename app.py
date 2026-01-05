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
        
        # Frontend se Sales Context aur Knowledge Base dono lena
        product_context = data.get('product_context', 'Nexus AI-OS Automation Services')
        kb_context = data.get('kb_context', 'No specific company data provided.')

        if 'chat_history' not in session:
            session['chat_history'] = []

        search_data = ""
        if any(word in user_query.lower() for word in ["find", "search", "leads", "business"]):
            raw_results = search_leads(user_query)
            if raw_results:
                search_data = f"\n\nReal-time Search Results: {json.dumps(raw_results)[:2000]}"

        # --- HYBRID KNOWLEDGE PROMPT ---
        # Ab AI ko pata hoga ke Sales Pitch kahan se leni hai aur Support Info kahan se
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