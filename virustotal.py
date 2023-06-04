import os
import json
import requests
from dotenv import load_dotenv
from time import sleep
import argparse

# Returns file size in megabytes
def get_file_size(file_path):
    file_size = os.path.getsize(file_path)
    file_size / (1024 * 1024)
    return file_size / (1024 * 1024)

class VirusTotalClient:

    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'


    def get_upload_url(self):
        url = f'{self.base_url}/files/upload_url'
        headers = {'x-apikey': self.api_key, 'accept': 'application/json'}
        response = requests.get(url, headers=headers)
        return response.json()['data']
    
    def get_resource_report(self, resource_type, sha):
        url = f'{self.base_url}/{resource_type}/{sha}'
        headers = {'x-apikey': self.api_key}
        response = requests.get(url, headers=headers)
        return response

    def scan_file(self, file_path):
        file_size = get_file_size(file_path)
        url = f'{self.base_url}/files' if file_size < 32 else self.get_upload_url()
        # print(f'{url=}')
        files = {'file': open(file_path, 'rb')}
        headers = {'x-apikey': self.api_key, 'accept': 'application/json'}
        response = requests.post(url, files=files, headers=headers)
        return response

    def scan_url(self, url):
        url = f'{self.base_url}/urls'
        payload = f'url={url}'
        headers = {'x-apikey': self.api_key, 'accept': 'application/json'}
        response = requests.post(url, data=payload, headers=headers)
        return response

if __name__ == '__main__':
    # Load environment variable from .env file
    load_dotenv()
    API_KEY = os.getenv('API_KEY')

    # Retreive command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', dest='file_to_scan', help='File to scan', required=False)
    args = parser.parse_args()
    file_name = args.file_to_scan

    # Set upload path
    basedir = os.path.abspath(os.path.dirname(__file__)) + '/'
    uploadsdir = os.path.join(basedir, 'uploads')

    if API_KEY:
        client = VirusTotalClient(API_KEY)
        file_path = f'{uploadsdir}/{file_name}'

        # Scan the file
        response = client.scan_file(file_path)

        if response.ok:
            response_data = response.json()
            analysis_id = response_data['data']['id']
            print(f"File successfully submitted for scanning. Analysis ID: {analysis_id}")
            analysis_response = client.get_file_analysis(analysis_id)
            file_id = analysis_response.json()['meta']['file_info']['sha256']
            file_report = client.get_file_report(file_id)
        else:
            print(f"Scan request failed: {response.text}")
    else:
        print("Please set the VIRUSTOTAL_API_KEY environment variable.")