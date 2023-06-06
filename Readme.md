## Install Dependencies

- pip install -r requirements.txt

## Setup Flask App
- Create a `.env` and set the `API_KEY` to your virustotal api key.
- python app.py

## Setup DB
- flask shell
- from models import db, Analysis
- db.create_all()
- flask db upgrade # setup db migrations

## VT Analysis Dashboard

![Scan Resource Page](./screenshots/scan_resource.png)

![Scan Results Page](./screenshots/scan_results.png)

![Scan Engine Results Page](./screenshots/scan_engine_results.png)