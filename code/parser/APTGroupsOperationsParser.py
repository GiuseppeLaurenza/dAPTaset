from string import punctuation

import gspread
import pandas as pd
from nltk import word_tokenize, pos_tag
from nltk.corpus import wordnet, stopwords
from nltk.probability import FreqDist
from nltk.stem import WordNetLemmatizer


class APTGroupsOperationsParser:

    def __init__(self, spreadsheet_url):
        gc = gspread.public()
        sheet = gc.open_by_url(spreadsheet_url)
        worksheet_list = sheet.worksheets()
        self.sheets = dict()
        self.columns_dict = dict()
        self.columns_dict["not parse"] = ['README', '_Download', '_Schemes', '_Malware', '_Sources']
        self.columns_dict["China"] = ['Common Name', 'CrowdStrike', 'IRL', 'Kaspersky', 'Secureworks', 'Mandiant',
                                      'FireEye', 'Symantec', 'iSight', 'Cisco (Sourcefire/VRT > Talos)',
                                      'Palo Alto Unit 42', 'Targets']
        self.columns_dict["Russia"] = ['Common Name', 'Other Name 1', 'Other Name 2', 'Other Name 3', 'Other Name 4',
                                       'Other Name 5', 'Other Name 6', 'Other Name 7', 'Other Name 8', 'Other Name 9',
                                       'Other Name 10', 'Other Name 11', 'Other Name 12', 'Secureworks', 'Operation 1',
                                       'Operation 2', 'Operation 3', 'Operation 4', 'Operation 5', 'Operation 6',
                                       'Operation 7', 'Targets']

        self.columns_dict["North Korea"] = ['Common Name', 'CrowdStrike', 'Talos Group', 'Dell Secure Works',
                                            'Other Name 1',
                                            'Other Name 2', 'Other Name 3', 'Other Name 4', 'Other Name 5',
                                            'Other Name 6',
                                            'Other Name 7', 'Other Name 8', 'Rep. of Korea FSI', 'Targets']

        self.columns_dict["Iran"] = ['Common Name', 'Other Name 1', 'Other Name 2', 'Other Name 3', 'Other Name 4',
                                     'Other Name 5',
                                     'FireEye Name', 'Cisco Name', 'Secureworks', 'Symantec', 'Targets']

        self.columns_dict["Israel"] = ['Common Name', 'Other Name 1', 'Other Name 2', 'Other Name 3', 'NSA', 'Targets']

        self.columns_dict["NATO"] = ['Common Name', 'Other Name 1', 'Other Name 2', 'Other Name 3', 'Other Name 4',
                                     'Symantec',
                                     'Kaspersky', 'Targets']

        self.columns_dict["Middle East"] = ['Common Name', 'Other Name 1', 'Other Name 2', 'Targets']

        self.columns_dict["Others"] = ['Common Name', 'Other Name 1', 'Other Name 2', 'Other Name 3', 'Other Name 4',
                                       'Other Name 5', 'Targets']

        self.columns_dict["Unknown"] = ['Common Name', 'Other Name 1', 'Other Name 2', 'Other Name 3', 'Other Name 4',
                                        'Other Name 5', 'NSA', 'Microsoft', 'FireEye', 'Targets']

        for sh in worksheet_list:
            if (sh.title not in self.columns_dict["not parse"]):
                row_list = sh.get_all_values()
                df = pd.DataFrame(row_list[2:], columns=row_list[1])
                self.sheets[sh.title] = df

    def __get_wordnet_pos(treebank_tag):
        if treebank_tag.startswith('J'):
            return wordnet.ADJ
        elif treebank_tag.startswith('V'):
            return wordnet.VERB
        elif treebank_tag.startswith('N'):
            return wordnet.NOUN
        elif treebank_tag.startswith('R'):
            return wordnet.ADV
        else:
            return wordnet.NOUN

    def get_lem_target(self):
        stop_words = stopwords.words('english')
        lemming_list = []
        lemmatizer = WordNetLemmatizer()
        target_list = []
        for key in self.sheets:
            current_sheet = self.sheets[key]
            for elem in current_sheet.iterrows():
                current_row = elem[1]
                target_string = current_row["Targets"]
                target_list.append(target_string)

        for target_string in target_list:
            text = word_tokenize(target_string)
            tagged_words = pos_tag(text)
            for elem in tagged_words:
                if elem[1] in punctuation:
                    continue
                if elem[0].lower() in stop_words:
                    continue
                lemming_list.append(lemmatizer.lemmatize(elem[0].lower(), __get_wordnet_pos(elem[1])))
        freq = FreqDist(lemming_list)
        most_common = freq.most_common(70)

        to_remove = ["target", "threat", "actor", "sector", "organization", "espionage", "company", "purpose", "south",
                     "united", "u.s.", "state", "asia", "east", "kroea", "middle", "japan", "include", "russia", "firm",
                     "group", "compromise", "primarily", "country", "israel", "provider", "service", "right", "saudi",
                     "iran", "\'s", "private", "hong", "taiwan", "medium", "activist", "u", "india", "human", "china",
                     "use", "kong", "southeast", "well", "central", "oil", "eastern", "arabia", "base", "agency",
                     "korea"]

        lem = [x[0] for x in most_common if x[0] not in to_remove]

        return lem
