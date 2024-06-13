# backend/app.py
from flask import Flask, request, jsonify
import requests
import base64

app = Flask(__name__)

API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'  # Reemplaza con tu API key de VirusTotal

def get_url_id(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return url_id

def get_url_report(url):
    url_id = get_url_id(url)
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)
    return response.json()

@app.route('/analyze', methods=['POST'])
def analyze():
    urls = request.json.get('urls', [])
    results = []
    for url in urls:
        report = get_url_report(url)
        url_info = {
            'url': url,
            'malicious': False,
            'score': 0,
            'detections': [],
            'top_malicious': [],
            'top_non_malicious': []
        }

        if 'data' in report:
            attributes = report['data']['attributes']
            url_info['score'] = attributes['last_analysis_stats']['malicious']
            url_info['malicious'] = url_info['score'] > 0
            detections = attributes['last_analysis_results']
            for engine, result in detections.items():
                url_info['detections'].append({
                    'engine': engine,
                    'result': result['category']
                })

            malicious_engines = [d['engine'] for d in url_info['detections'] if d['result'] == 'malicious']
            non_malicious_engines = [d['engine'] for d in url_info['detections'] if d['result'] != 'malicious']

            url_info['top_malicious'] = malicious_engines[:5]
            url_info['top_non_malicious'] = non_malicious_engines[:5]

        results.append(url_info)
    return jsonify(results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
