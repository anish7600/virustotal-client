from flask import Flask, render_template, request
from flask_bootstrap import Bootstrap
from virustotal import VirusTotalClient
from dotenv import load_dotenv
from models import db, Analysis
import requests
import os
import hashlib
from sqlalchemy.orm import class_mapper

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

@app.route('/', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files['file']
    file.save('uploads/' + file.filename)

    file_path = os.path.abspath(os.path.join(uploadsdir, file.filename))
    file_sha_256 = calculate_file_sha256(file_path)

    if Analysis.query.filter_by(file_id=file_sha_256).first():
        return render_template('dashboard.html', msg=f'File {file.filename} already scanned and analyzed.')
    else:
        # Initialize the VirusTotalClient
        client = VirusTotalClient(API_KEY)
        
        # Scan the file
        response = client.scan_file(file_path)

        if response.ok:
            scan_data = response.json()
            analysis_id = scan_data['data']['id']
            response = client.get_file_analysis(analysis_id)
            if response.status_code == 200:
                analysis_data = response.json()
            else:
                # Error occurred while retrieving the file report
                error_msg = f'Error retrieving analysis report for Analysis ID: {analysis_id}. Status code: {response.status_code}'
                return render_template('error.html', error_message=error_msg)

            file_id = analysis_data['meta']['file_info']['sha256']
            response = client.get_file_report(file_id)

            if response.status_code == 200:
                file_report_data = response.json()
                analysis_stats = file_report_data['data']['attributes']['last_analysis_stats']
                malicious_count = analysis_stats['malicious']
                suspicious_count = analysis_stats['suspicious']
                analysis = Analysis(file_id=file_id, malicious_count=malicious_count, suspicious_count=suspicious_count)
                db.session.add(analysis)
                db.session.commit()
            else:
                # Error occurred while retrieving the file report
                error_msg = f'Error retrieving file report for File ID: {file_id}. Status code: {response.status_code}'
                return render_template('error.html', error_message=error_msg)

            return render_template('dashboard.html', msg=f"File successfully submitted for scanning. Analysis ID: {analysis_id}")
        else:
            error_msg = f'Scan request failed: {response.text}'
            return render_template('error.html', error_message=error_msg)

@app.route('/scan_result', methods=['GET'])
def scan_result():
    analysis_objects = Analysis.query.all()
    serialized_analysis_objects = [serialize(obj) for obj in analysis_objects]

    return render_template('scan_result.html', analysis_stats=serialized_analysis_objects)

app.run(port=5000)