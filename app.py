from flask import Flask, render_template, request, jsonify
from domain_recon import DomainReconnaissance, generate_ai_insights
from openai import OpenAI
import os
from dotenv import load_dotenv
import plotly
import plotly.express as px
import json
import pandas as pd
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
load_dotenv()

# Initialize OpenAI client
try:
    openai_api_key = os.getenv('OPENAI_API_KEY')
    if not openai_api_key:
        logger.warning("OPENAI_API_KEY not found in environment variables")
    client = OpenAI(api_key=openai_api_key)
except Exception as e:
    logger.error(f"Error initializing OpenAI client: {str(e)}")
    client = None

def generate_traffic_chart(domain_data):
    """Generate a traffic analysis chart"""
    # This is a mock data - in real implementation, you would get this from analytics APIs
    dates = pd.date_range(start='2023-01-01', end='2023-12-31', freq='M')
    traffic = pd.Series([1000, 1200, 1500, 1300, 1400, 1600, 1800, 1700, 1900, 2000, 2200, 2400], index=dates)
    
    fig = px.line(x=dates, y=traffic, title='Monthly Traffic Analysis')
    fig.update_layout(
        xaxis_title='Date',
        yaxis_title='Traffic Volume',
        template='plotly_dark'
    )
    
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    domain = request.form.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    # Initialize domain reconnaissance
    recon = DomainReconnaissance(domain)
    results = recon.run()
    
    # Generate AI insights using the function from domain_recon.py
    ai_insights = generate_ai_insights(domain, results)
    
    # Generate traffic chart
    traffic_chart = generate_traffic_chart(results)
    
    # Prepare the response data
    response_data = {
        'domain': domain,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'whois': results.get('whois', {}),
        'dns': results.get('dns', {}),
        'ssl': results.get('ssl', {}),
        'ssl_vulnerabilities': results.get('ssl_vulnerabilities', []),
        'security_headers': results.get('security_headers', {}),
        'vulnerabilities': results.get('virustotal', {}).get('data', {}).get('attributes', {}),
        'shodan_data': results.get('shodan', {}),
        'ai_insights': ai_insights,
        'traffic_chart': traffic_chart
    }
    
    return render_template('results.html', data=response_data)

if __name__ == '__main__':
    app.run(debug=True) 