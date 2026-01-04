import requests

url = "http://127.0.0.1:5000/ask-agent"
data = {"message": "Hello, I am a business owner in Spain. How can you help me make more money?"}

response = requests.post(url, json=data)
print(response.json())