import hashlib
import json
import os

import pandas as pd
import requests


class VirusTotalParser:
    def __init__(self, apikey, url, temp_folder):
        self.apikey = apikey
        self.url = url
        self.temp = temp_folder + "vt_result/"

    def get_report(self, query, query_type, to_file=False, all_info=False):
        if query_type == "ip":
            query_type = "ip-address"
            params = {'apikey': self.apikey, 'ip': '', "allinfo": 1}
            params["ip"] = query
            filename = hashlib.sha1(query.encode('utf-8')).hexdigest()
            filepath = self.temp + filename + '.json'
        elif query_type == "url":
            params = {'apikey': self.apikey, 'resource': '', "allinfo": 1}
            params["resource"] = query
            filename = hashlib.sha1(query.encode('utf-8')).hexdigest()
            filepath = self.temp + filename + '.json'
        else:
            params = {'apikey': self.apikey, 'resource': '', "allinfo": 1}
            params["resource"] = query
            filepath = self.temp + query + '.json'

        if os.path.exists(filepath):
            with open(filepath, "r") as inputfile:
                json_response = json.load(inputfile)
        else:
            response = requests.get(self.url + query_type + "/report",
                                    params=params)
            if response.status_code != 200:
                return pd.DataFrame(columns=["positives"])
            json_response = response.json()
            if to_file:
                with open(filepath, 'w') as outfile:
                    json.dump(json_response, outfile)
        if all_info:
            try:
                result = pd.DataFrame(json_response)
                result[[0, 'detail', 'detected', 'result']] = result["scans"].apply(pd.Series)
                result = result.drop([0, "scans"], 1)
                result["detected"] = result["detected"].fillna(False)
                result["positives"] = result["positives"].fillna(0)
                return result
            except Exception as e:
                return pd.DataFrame([{"positives": 0, "detected": False}])
        else:
            hashes = {"md5": json_response.get("md5"), "sha1": json_response.get("sha1"),
                      "sha256": json_response.get("sha256"), "sha512": json_response.get("sha512")}
            return hashes
