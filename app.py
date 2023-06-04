from flask import Flask, render_template, request
from flask_bootstrap import Bootstrap
from virustotal import VirusTotalClient
from dotenv import load_dotenv
from models import db, Analysis
import requests
import os
import hashlib
from sqlalchemy.orm import class_mapper
from time import sleep

# Load environment variable from .env file
load_dotenv()
API_KEY = os.getenv('API_KEY')

basedir = os.path.abspath(os.path.dirname(__file__)) + '/'
uploadsdir = os.path.join(basedir, 'uploads')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' +  basedir + 'analysis.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
bootstrap = Bootstrap(app)


def calculate_file_sha256(file_path):
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as file:
        # Read the file in chunks to handle large files efficiently
        for chunk in iter(lambda: file.read(4096), b''):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()

def serialize(obj):
    """
    Serialize SQLAlchemy object to a dictionary.
    """
    columns = [c.key for c in class_mapper(obj.__class__).columns]
    return {c: getattr(obj, c) for c in columns}

def save_analysis_stats_to_db(file_sha_256, file_report_data):
    analysis_stats = file_report_data['data']['attributes']['last_analysis_stats']
    malicious_count = analysis_stats['malicious']
    suspicious_count = analysis_stats['suspicious']

    # check if file already exists in db
    analysis_obj = Analysis.query.filter_by(file_id=file_sha_256).first()
    if analysis_obj:
        analysis_obj.malicious_count = malicious_count
        analysis_obj.suspicious_count = suspicious_count
    else:
        analysis = Analysis(file_id=file_sha_256, malicious_count=malicious_count, suspicious_count=suspicious_count)
        db.session.add(analysis)
    db.session.commit()


@app.route('/', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files['file']
    file.save('uploads/' + file.filename)

    file_path = os.path.abspath(os.path.join(uploadsdir, file.filename))
    file_sha_256 = calculate_file_sha256(file_path)

    # Initialize the VirusTotalClient
    client = VirusTotalClient(API_KEY)

    # Get File Report
    response = client.get_file_report(file_sha_256)
    file_report_data = response.json()
    if response.status_code == 200:
        save_analysis_stats_to_db(file_sha_256, file_report_data)
        return render_template('dashboard.html', msg=f'File {file.filename} already scanned and analyzed by VirusTotal.')
    elif response.status_code == 404:
        # Upload the file to VT for scanning
        client.scan_file(file_path)
        response = client.get_file_report(file_sha_256).json()

        # check if analysis is finished
        last_analysis_results = response['data']['attributes']['last_analysis_results']
        attempts = 0
        while not last_analysis_results and attempts < 5:
            attempts += 1
            response = client.get_file_report(file_sha_256).json()
            last_analysis_results = response['data']['attributes']['last_analysis_results']
            if last_analysis_results:
                break
            else:
                print(f"Analysis in progress, waiting...")
                sleep(10)

        if not last_analysis_results:
            return render_template('dashboard.html', msg=f'Analysis in progress! File Id: {file_sha_256}')
        else:
            save_analysis_stats_to_db(file_sha_256, response)
            return render_template('dashboard.html', msg=f'File {file.filename} scanned and analyzed by VirusTotal.')

@app.route('/scan_result', methods=['GET'])
def scan_result():
    analysis_objects = Analysis.query.all()
    serialized_analysis_objects = [serialize(obj) for obj in analysis_objects]

    return render_template('scan_result.html', analysis_stats=serialized_analysis_objects)

app.run(port=5000)