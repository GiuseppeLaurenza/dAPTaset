import errno
import json
import os
import pickle
from json import JSONDecodeError

import requests


class MalshareParser:
    def __init__(self, key, url, temp_folder):
        self.apikey = key
        self.temp = temp_folder + "ms_result/"
        try:
            os.makedirs(self.temp)
        except OSError as exc:  # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(self.temp):
                pass
            else:
                raise
        self.url = url

    def search_by_name(self, software_name, to_file=False):
        filepath = self.temp + software_name + '.p'
        dict_list = []
        if os.path.exists(filepath):
            with open(filepath, "rb") as inputfile:
                dict_list = pickle.load(inputfile)
        else:
            params = {'api_key': self.apikey, 'action': 'search', "query": ""}
            params["query"] = software_name
            response = requests.get(self.url, params=params)
            if (len(response.text) > 0):
                json_list = ['{"md5"' + x for x in response.text.split('{"md5"')]
                for x in json_list[1:]:
                    try:
                        dict_list.append(json.loads(x))
                    except JSONDecodeError as e:
                        print(x)
                        continue
            if (to_file):
                with open(filepath, "wb") as outputfile:
                    pickle.dump(dict_list, outputfile)
        return dict_list
