from string import punctuation


def clean_string(raw_string, strip=True):
    if not isinstance(raw_string, str):
        raw_string = str(raw_string)
    remove_punct_map = dict.fromkeys(map(ord, punctuation))
    cleaned_string = raw_string.translate(remove_punct_map)
    if strip:
        cleaned_string = cleaned_string.replace(" ", "").lower()
    return cleaned_string


def lowercase_nullcheck(old_string):
    if old_string is not None:
        return old_string.lower()
    return old_string


def single_target_extractor(raw_text):
    stopwords = set(
        ["organizations", "sectors", "entities", "organization", "sector", "entity", "actor", "actors", "target",
         "targets", "compromises", "compromise", "threat", "threats", "computer", "computers", "network", "networks",
         "institute",
         "institutes", "republic", "middle", "purpose", "purposes", "firms", "firm", "application", "applications"])
    cleaned_text = raw_text.lower().replace("(", "").replace(")", "").replace(" and", ",").replace(",,", ",")
    text = word_tokenize(cleaned_text)
    token_list = pos_tag(text)
    cleaned_list = []
    for current_token in token_list:
        if (current_token[1].startswith("NN")):
            if current_token[0] not in stopwords:
                if current_token[0].lower() == "hong" or current_token[0].lower() == "kong":
                    cleaned_list.append("hong-kong")
                else:
                    cleaned_list.append(current_token[0])
    return cleaned_list
