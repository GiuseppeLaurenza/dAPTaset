from deeppavlov import build_model, configs
from nltk import word_tokenize, pos_tag
from nltk.stem import WordNetLemmatizer


class deepLearningModel:
    def __init__(self):
        self.model = build_model(configs.squad.squad, download=True)
        # self.model = ""
        self.stopwords = set(
            ["organizations", "sectors", "entities", "organization", "sector", "entity", "actor", "actors", "target",
             "targets", "compromises", "compromise", "threat", "threats", "computer", "computers", "network",
             "networks", "institute",
             "institutes", "republic", "middle", "purpose", "purposes", "firms", "firm", "application", "applications"])
        self.lemmatizer = WordNetLemmatizer()

    def __single_target_extractor(self, raw_text):
        cleaned_text = raw_text.lower().replace("(", "").replace(")", "").replace(" and", ",").replace(",,", ",")
        text = word_tokenize(cleaned_text)
        token_list = pos_tag(text)
        cleaned_list = []
        for current_token in token_list:
            if (current_token[1].startswith("NN")):
                if current_token[0] not in self.stopwords:
                    if current_token[0].lower() == "hong" or current_token[0].lower() == "kong":
                        cleaned_list.append(self.lemmatizer.lemmatize("hong-kong"))
                    else:
                        cleaned_list.append(self.lemmatizer.lemmatize(current_token[0]))
        return list(set(cleaned_list))

    def get_target(self, text):
        extracted_target = self.model([text], ['Which are the targets?'])[0][0]
        return self.__single_target_extractor(extracted_target)

    def get_nations(self, text):
        extracted_nations = self.model([text], ['Which are the attacked countries?'])[0][0]
        return self.__single_target_extractor(extracted_nations)
