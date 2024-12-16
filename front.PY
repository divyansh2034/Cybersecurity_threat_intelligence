import requests
import psycopg2
from datetime import datetime

API_KEY = 'fa5b45f78251ca5fa46f741048b99ae4b92df6e26878352543c9c2ab95ac0994'
BASE_URL = 'https://www.virustotal.com/api/v3/analyses/u-42d61ff2d2d4bf7c562825a79c8f9b5a4f22b2d53af96a02afcc6e2ee5539c90-1733566781'

headers = {"x-apikey": API_KEY}
data = {"url": BASE_URL}

response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
if response.status_code == 200:
    analysis_id = response.json()["data"]["id"]
    print(f"Analysis ID: {analysis_id}")
else:
    print(f"Error: {response.status_code}, {response.text}")

connection = psycopg2.connect(
    dbname="cybersecurity_db",
    user="postgres",
    password="divyansh@2004",
    host="localhost",
    port="5432"
)
cursor = connection.cursor()

def insert_threat_data(response_json):
    try:
        data = response_json["data"]
        attributes = data["attributes"]
        stats = attributes["stats"]
        results = attributes["results"]

        indicator = data["id"]
        type = "url"  
        severity = (
            "high" if stats["malicious"] > 0 else
            "medium" if stats["suspicious"] > 0 else
            "low"
        )

        for engine_name, result_data in results.items():
            source = engine_name
            description = result_data.get("result", "No description")
            last_updated = datetime.now()

            query = """
            INSERT INTO ThreatIndicators (source, indicator, type, severity, description, last_updated)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (indicator, source) DO UPDATE 
            SET severity = EXCLUDED.severity, description = EXCLUDED.description, last_updated = EXCLUDED.last_updated;
            """
            cursor.execute(query, (source, indicator, type, severity, description, last_updated))

        connection.commit()
    except Exception as e:
        print(f"Database Error: {e}")
        connection.rollback()

def get_analysis_report(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/u-42d61ff2d2d4bf7c562825a79c8f9b5a4f22b2d53af96a02afcc6e2ee5539c90-1733566781"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return None

analysis_id = "u-42d61ff2d2d4bf7c562825a79c8f9b5a4f22b2d53af96a02afcc6e2ee5539c90-1733566781"
response_json = get_analysis_report(analysis_id)
if response_json:
    insert_threat_data(response_json)

cursor.close()
connection.close()
