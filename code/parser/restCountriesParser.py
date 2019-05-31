import json
import urllib

import pandas as pd
from nltk.stem import WordNetLemmatizer


class restCountriesParser:
    def __init__(self, json_url):
        self.json_url = json_url
        with urllib.request.urlopen(json_url) as url:
            data = json.loads(url.read().decode())
            self.df = pd.DataFrame(data)

    def __extract_country_data(self, elem):
        lemmatizer = WordNetLemmatizer()
        result = []
        if (elem["demonym"].lower() == "british"):
            result.append("uk")
        elif elem["demonym"].lower() == "american":
            if (elem["nativeName"] == "United States"):
                result.append("usa")
                result.append("u.s.")
            del elem["demonym"]
        for key in elem.index:
            if isinstance(elem[key], list):
                for x in elem[key]:
                    if len(x) > 3:
                        result.append(x.lower())
            else:
                if len(elem[key]) > 3:
                    result.append(lemmatizer.lemmatize(elem[key].lower()))

        return result

    def clean_df(self):

        self.df["alias"] = self.df[["demonym", "altSpellings", "capital", "nativeName", "name"]].apply(
            self.__extract_country_data, 1)

    def get_alias_set(self):
        self.alias = set([x for sublist in self.df["alias"] for x in sublist])
