from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum, JSON

db = SQLAlchemy()

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resource_type = db.Column(Enum('file', 'url'), nullable=False)
    resource_name = db.Column(db.String(100), nullable=False)
    resource_id = db.Column(db.String(300), unique=True)
    last_analysis_results = db.Column(JSON)
    last_analysis_stats = db.Column(JSON)