from flask import Flask, render_template, request
from flask_migrate import Migrate
from flask_bootstrap import Bootstrap
from virustotal import VirusTotalClient
from dotenv import load_dotenv
from models import db, Analysis
import os
import hashlib
from sqlalchemy.orm import class_mapper
from time import sleep
import json

# Load environment variable from .env file
load_dotenv()
API_KEY = os.getenv('API_KEY')

basedir = os.path.abspath(os.path.dirname(__file__)) + '/'
uploadsdir = os.path.join(basedir, 'uploads')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' +  basedir + 'analysis.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

bootstrap = Bootstrap(app)
migrate = Migrate(app, db)
db.init_app(app)

def calculate_file_sha256(file_path):
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as file:
        # Read the file in chunks to handle large files efficiently
        for chunk in iter(lambda: file.read(4096), b''):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()

def get_analysis_status(client, resource_type, sha, response):
    last_analysis_results = response['data']['attributes']['last_analysis_results']
    attempts = 0
    while not last_analysis_results and attempts < 5:
        attempts += 1
        response = client.get_resource_report(resource_type, sha).json()
        last_analysis_results = response['data']['attributes']['last_analysis_results']
        if last_analysis_results:
            break
        else:
            print(f"Analysis in progress, waiting...")
            sleep(10)

    return last_analysis_results

def calculate_url_sha256(url):
    return hashlib.sha256(url.encode()).hexdigest()

def save_analysis_stats_to_db(sha, data):
    resource_type = data['data']['type']
    resource_name = data['data']['attributes']['names'][0] if resource_type == 'file' else data['data']['attributes']['url']
    last_analysis_stats = data['data']['attributes']['last_analysis_stats']
    last_analysis_results = data['data']['attributes']['last_analysis_results']

    analysis = Analysis(resource_id=sha, resource_name=resource_name, resource_type=resource_type, last_analysis_results=last_analysis_results, last_analysis_stats=last_analysis_stats)
    db.session.add(analysis)
    db.session.commit()

@app.route('/', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files['file']
    url = request.form['url']
    resource_type = 'files' if file else 'urls'
    # Initialize the VirusTotalClient
    client = VirusTotalClient(API_KEY)

    # Analyze File
    if file:
        file.save('uploads/' + file.filename)
        file_path = os.path.abspath(os.path.join(uploadsdir, file.filename))
        file_sha_256 = calculate_file_sha256(file_path)

        # Get File Report
        response = client.get_resource_report(resource_type, file_sha_256)
        file_report_data = response.json()
        if response.status_code == 200:
            save_analysis_stats_to_db(file_sha_256, file_report_data)
            return render_template('dashboard.html', msg=f'File {file.filename} already scanned and analyzed by VirusTotal.')
        elif response.status_code == 404:
            # Upload the file to VT for scanning
            client.scan_file(file_path)
            response = client.get_resource_report(resource_type, file_sha_256).json()

            # check if analysis is finished
            is_pending = get_analysis_status(client, resource_type, file_sha_256, response)           

            if is_pending:
                return render_template('dashboard.html', msg=f'Analysis in progress! File Id: {file_sha_256}')
            else:
                save_analysis_stats_to_db(file_sha_256, response)
                return render_template('dashboard.html', msg=f'File {file.filename} scanned and analyzed by VirusTotal.')
    # Analyze URL
    if url:
        url_sha = calculate_url_sha256(url)
        response = client.scan_url(url)
        url_id = response.json()['data']['id'].split('-')[1]
        response = client.get_resource_report(resource_type, url_id).json()

        # check if analysis is finished
        last_analysis_results = get_analysis_status(client, resource_type, url_id, response)

        if not last_analysis_results:
            return render_template('dashboard.html', msg=f'Analysis in progress! URL Id: {url_id}')
        else:
            save_analysis_stats_to_db(url_id, response)
            return render_template('dashboard.html', msg=f'URL {url_id} scanned and analyzed by VirusTotal.')

@app.route('/scan_results', methods=['POST'])
def scan_result():
    resource_type = request.form.get('resource_type')
    resources = Analysis.query.filter_by(resource_type=resource_type)
    return render_template('scan_results.html', resources=resources)

@app.route('/scan_engine_results', methods=['GET'])
def scan_engine_results():
    resc_id = request.args.get('id')
    resc = Analysis.query.filter_by(resource_id=resc_id).first()
    return render_template('scan_engine_results.html', resource=resc)

if __name__ == '__main__':
    app.run(port=5000)