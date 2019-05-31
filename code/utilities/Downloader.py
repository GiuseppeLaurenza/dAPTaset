import hashlib
import json
import os
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


class Downloader():

    def __init__(self, download_folder):
        self.download_folder = download_folder

    def get_download_url(self, page):
        soup = BeautifulSoup(page, 'lxml')
        scripts = soup.find('body').find_all('script')
        sections = scripts[-1].contents[0].split(';')
        app_api = json.loads(sections[0].split('=')[1])['/app-api/enduserapp/shared-item']
        box_url = "https://app.box.com/index.php"
        box_args = "?rm=box_download_shared_file&shared_name={}&file_id={}"
        file_url = box_url + box_args.format(app_api['sharedName'], 'f_{}'.format(app_api['itemID']))
        return file_url

    def download_from_appbox(self, document_url, report_filename):
        try:
            report_splash = requests.get(document_url).text
            file_url = self.get_download_url(report_splash)
            hash_check = hashlib.sha1()
            download_path = os.path.join(self.download_folder, report_filename)
            report_file = requests.get(file_url, stream=True)
            with open(download_path, 'wb') as f:
                for chunk in report_file.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        hash_check.update(chunk)
            print("[+] Successfully downloaded {}".format(download_path))
            return download_path
        except Exception as unexpected_error:
            message = "[!] Download failure for {}".format(report_filename)
            print(message, unexpected_error)
            return None

    def download_document(self, document_url, filename=None):
        if (filename is None):
            url_path = urlparse(document_url)
            filename = os.path.basename(url_path.path)
            if filename == "":
                filename = os.path.basename(os.path.normpath(url_path.path))
            if filename == "":
                filename = url_path.netloc
        destination = self.download_folder + str(filename)
        print("Download Documents from " + document_url + " to " + destination)
        headers = {'Content-type': 'application/json',
                   'User-Agent': 'Mozilla/5.0 (X11; Linux i686; rv:64.0) Gecko/20100101 Firefox/64.0'}
        try:
            response = requests.get(document_url, headers=headers, verify=False)
            if document_url.endswith(".pdf"):
                with open(destination, "wb") as outputfile:
                    outputfile.write(response.content)
            else:
                with open(destination, "w") as outputfile:
                    outputfile.write(response.text)
            hasher = hashlib.sha1()
            with open(destination, 'rb') as afile:
                buf = afile.read()
                hasher.update(buf)
            return {"path": destination, "hash": hasher.hexdigest()}
        except requests.exceptions.ConnectionError as e:
            return {"path": destination, "hash": None}

