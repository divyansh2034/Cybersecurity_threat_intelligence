from flask import Flask, request, jsonify
import requests
import psycopg2

app = Flask(__name__)

# API credentials
API_KEY = 'fa5b45f78251ca5fa46f741048b99ae4b92df6e26878352543c9c2ab95ac0994'
API_URL = 'https://www.virustotal.com/api/v3/analyses/u-dbae2d0204aa489e234eb2f903a0127b17c712386428cab12b86c5f68aa75867-1733395093'
# Database connection
conn = psycopg2.connect(
    dbname="cybersecurity_db",
    user="postgres",
    password="divyansh@2004",
    host="localhost",
    port="5432"
)
cursor = conn.cursor()

def fetch_threat_data():
    headers = {"x-apikey": API_KEY}
    response = requests.get(API_URL, headers=headers)

    # Debugging: Check status code and raw response
    print("Status Code:", response.status_code)
    print("Response Content:", response.text)

    if response.status_code == 200:
        try:
            data = response.json()
            for threat in data.get('data', []):  # Safely handle missing 'data' key
                insert_into_db(
                    source=threat['attributes'].get('source', 'Unknown'),
                    indicator=threat['attributes'].get('indicator', 'N/A'),
                    type=threat['attributes'].get('type', 'N/A'),
                    severity=threat['attributes'].get('severity', 'N/A'),
                    description=threat['attributes'].get('description', 'N/A')
                )
        except requests.exceptions.JSONDecodeError:
            print("Invalid JSON response. Content:", response.text)
    else:
        print(f"Failed to fetch data: {response.status_code} - {response.text}")

def insert_into_db(source, indicator, type, severity, description):
    query = """
        INSERT INTO ThreatIndicators (source, indicator, type, severity, description)
        VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(query, (source, indicator, type, severity, description))
    conn.commit()
    
@app.route('/scan', methods=['POST'])
def scan_website():
    url = request.json.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400
    # Generate API request dynamically
    api_url = f"https://www.virustotal.com/api/v3/analyses/u-dbae2d0204aa489e234eb2f903a0127b17c712386428cab12b86c5f68aa75867-1733395093"
    headers = {"x-apikey": API_KEY}
    response = requests.post(api_url, headers=headers, data={'url': url})
    # Process the response
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({"error": "Failed to fetch data"}), response.status_code

if __name__ == "__main__":
    fetch_threat_data()
