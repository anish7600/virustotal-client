## Install Dependencies

- pip install -r requirements.txt


## Run script
- Create a `.env` and set the `API_KEY` to your virustotal api key.
- Add files to scan in uploads directory
- python virustotal.py -f [file_name]

## Setup DB
- flask shell
- from models import db, Analysis
- db.create_all()

## Run Flask App
- python app.py