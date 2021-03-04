import json
import urllib.request

import pandas as pd


class mispGalaxyParser:
    def __init__(self, threat_actor_url):
        with urllib.request.urlopen(threat_actor_url) as url:
            data = json.loads(url.read().decode())
        self.df_threat = pd.DataFrame(data["values"])
        self.df_threat[
            [0, 'attribution-confidence', 'capabilities', 'cfr-suspected-state-sponsor', 'cfr-suspected-victims',
             'cfr-target-category', 'cfr-type-of-incident', 'country', 'mode-of-operation', 'motive', 'refs',
             'since', 'synonyms', 'victimology','spoken-language', 'suspected-victims', 'threat-actor-classification']] = self.df_threat["meta"].apply(pd.Series)
        self.df_threat = self.df_threat.drop([0], 1)
        self.df_threat = self.df_threat.fillna("")
