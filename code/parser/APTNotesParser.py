import json

import pandas as pd
import requests


class APTNotesParser:
    def __init__(self, aptnotes_url):
        APTnotes = requests.get(aptnotes_url)
        if APTnotes.status_code == 200:
            APT_reports = json.loads(APTnotes.text)
            APT_reports.reverse()
        else:
            APT_reports = []
        # Reverse order of reports in order to download newest to oldest
        self.reports = pd.DataFrame(APT_reports)
