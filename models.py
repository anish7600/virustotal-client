from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.String(300), unique=True)
    malicious_count = db.Column(db.Integer)
    suspicious_count = db.Column(db.Integer)

    def __init__(self, resource_id, malicious_count, suspicious_count):
        self.resource_id = resource_id
        self.malicious_count = malicious_count
        self.suspicious_count = suspicious_count
