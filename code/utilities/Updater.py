import hashlib

import pandas as pd

from parser.documentParser import parse_document
from utilities.Downloader import Downloader
from utilities.string_functions import clean_string


class Updater:
    def __init__(self, db, mitre_parser, go_parser, aptnotes_parser, vt_parser, ms_parser, cve_parser, country_parser,
                 galaxy_parser, temp_folder):
        self.db = db
        self.mitre_parser = mitre_parser
        self.go_parser = go_parser
        self.aptnotes_parser = aptnotes_parser
        self.vt_parser = vt_parser
        self.ms_parser = ms_parser
        self.cve_parser = cve_parser
        self.downloader = Downloader(temp_folder)
        self.country_parser = country_parser
        self.country_parser.clean_df()
        self.country_df = self.country_parser.df
        self.country_parser.get_alias_set()
        self.country_alias = self.country_parser.alias
        # self.deepLM = deepLearningModel()
        # self.model = self.deepLM.model
        self.deepLM = None
        self.model = None
        self.galaxy_parser = galaxy_parser


    def __insert_repo_from_url__(self, aptname, current_url, description, source):
        download_data = self.downloader.download_document(current_url)
        report_hash = download_data["hash"]
        file_path = download_data["path"]
        if report_hash is None:
            print("Impossible to save report from " + current_url)
            return None
        keywords_set = self.db.get_keywords()
        try:
            report_data = parse_document(file_path, keywords_set)
        except Exception as e:
            return None
        if (report_data is None):
            self.db.insert_unknown_report(report_hash, description, current_url, source)
            return None
        hash_df = report_data["hash"]
        found_keywords = report_data["keyword"]
        current_report_id = self.db.insert_report(report_hash, description, current_url, source, found_keywords)
        self.db.insert_apt_report_relation(aptname, current_report_id)
        if not hash_df.empty:
            for element in hash_df.iterrows():
                current_sample = element[1]
                sample_dict = current_sample.to_dict()
                sample_id = self.db.insert_sample(sample_dict)
                self.db.insert_sample_report_relation(sample_id, current_report_id)
            self.db.connection.commit()

        for type in ["url", "email", "ip"]:
            for address in report_data[type]:
                self.db.insert_network(address, type)
                self.db.insert_report_network_relation(current_report_id, address)
            self.db.connection.commit()

        for cve in report_data["cve"]:
            res = self.cve_parser.parse_cve(cve)
            self.db.insert_cve(res["name"], res["year"], res["affected_products"])
            self.db.insert_report_cve_relation(current_report_id, res["name"])
        self.db.connection.commit()

    def misp_galaxy_update(self):
        apt_set = set(self.db.get_all_apt())
        for elem in self.galaxy_parser.df_threat.iterrows():
            current_row = elem[1]
            if clean_string(current_row["value"]) in apt_set:
                mitre_aptname = clean_string(current_row["value"])
                alias_list = [x for x in current_row["synonyms"]]
            else:
                mitre_aptname = None
                alias_list = [clean_string(current_row["value"])]
                for alias in current_row["synonyms"]:
                    if clean_string(alias) in apt_set:
                        mitre_aptname = clean_string(alias)
                    else:
                        alias_list.append(alias)
            if mitre_aptname is None:
                continue
            for alias in alias_list:
                self.db.insert_alias(mitre_aptname, alias)
                self.db.insert_alias(mitre_aptname, clean_string(alias))
            country_search = self.country_df[self.country_df["alpha2Code"] == current_row["country"]]
            for country_elem in country_search.iterrows():
                current_country = country_elem[1]
                self.db.insert_organization(current_country["name"].lower())
                self.db.insert_apt_cos(mitre_aptname, current_country["name"].lower(), "suspected state sponsor")
            self.db.insert_organization(current_row["cfr-suspected-state-sponsor"].lower())
            self.db.insert_apt_cos(mitre_aptname, current_row["cfr-suspected-state-sponsor"], "suspected state sponsor")
            for suspected_victim in current_row["cfr-suspected-victims"]:
                self.db.insert_apt_cos(mitre_aptname, suspected_victim,
                                       "suspected victims")
            for suspected_target in current_row["cfr-target-category"]:
                self.db.insert_apt_cos(suspected_target, suspected_victim,
                                       "suspected victims")
            for current_url in current_row["meta"]["refs"]:
                self.__insert_repo_from_url__(mitre_aptname, current_url, current_row["description"],
                                              "misp_galaxy_external_reference")

    def mitre_update(self):
        group_df = self.mitre_parser.get_all_groups()
        old_reports = self.db.get_report_hashes()
        keywords_set = self.db.get_keywords()
        for row in group_df.iterrows():
            current_row = row[1]
            # if (current_row["hash"] in old_reports):
            #     continue
            cleaned_aptname = clean_string(current_row["name"])
            self.db.insert_apt(cleaned_aptname)
            self.db.insert_alias(cleaned_aptname, cleaned_aptname)
            self.db.insert_alias(cleaned_aptname, current_row["name"])
            url_references = pd.DataFrame(current_row["external_references"])
            mitre_url = url_references[url_references["source_name"] == "mitre-attack"]["url"][0]
            mitre_report_id = self.db.insert_report(current_row["hash"], current_row["description"], mitre_url, "mitre")
            self.db.insert_apt_report_relation(cleaned_aptname, mitre_report_id)
            current_dict = current_row.to_dict()
            malware_df = self.mitre_parser.get_malware_by_group(current_dict)
            tool_df = self.mitre_parser.get_tool_by_group(current_dict)
            for alias in current_row["aliases"]:
                self.db.insert_alias(cleaned_aptname, alias)
                self.db.insert_alias(cleaned_aptname, clean_string(alias))
                keywords_set.add(alias)
                keywords_set.add(clean_string(alias))
            for current_element in malware_df.iterrows():
                current_software = current_element[1]
                current_software_name = current_software['name']
                self.db.insert_software(current_software_name, mitre_report_id, False)
                software_aliases = current_software.get('x_mitre_aliases')
                if software_aliases is not None:
                    for software_alias in software_aliases:
                        self.db.insert_software(software_alias, mitre_report_id, False)
            for current_element in tool_df.iterrows():
                current_software = current_element[1]
                current_software_name = current_software['name']
                self.db.insert_software(current_software_name, mitre_report_id, True)
                software_aliases = current_software.get('x_mitre_aliases')
                if software_aliases is not None:
                    for software_alias in software_aliases:
                        self.db.insert_software(software_alias, mitre_report_id, True)
            self.db.connection.commit()
            for current_report_object in url_references[
                (url_references["source_name"] != "mitre-attack") & (url_references["url"].notna())].iterrows():
                current_report_row = current_report_object[1]
                current_url = current_report_row["url"].strip()
                self.__insert_repo_from_url__(cleaned_aptname, current_url, current_row["description"],
                                              "mitre_external_reference")
            techniques_df = self.mitre_parser.get_techniques_by_group(current_dict)
            for elem in techniques_df.iterrows():
                row = elem[1]
                self.db.insert_technique(row.to_dict())
                self.db.insert_report_technique(mitre_report_id, row["mitre_id"])
            self.db.connection.commit()

    def insert_gspread_alias(self, sheet_title, current_row):
        apt_list = self.db.get_all_apt()
        alias_columns = [x for x in self.go_parser.columns_dict[sheet_title] if "Targets" not in x]
        apt_name_list = list(filter(None, list(current_row[alias_columns].values)))
        apt_name_list = list(filter(lambda x: x != '?', apt_name_list))
        clean_aptname_list = [clean_string(x) for x in apt_name_list]
        mitre_aptname = None
        target_string = current_row["Targets"]
        for x in clean_aptname_list:
            if x in apt_list:
                mitre_aptname = x
                break
        if mitre_aptname is not None:
            if not isinstance(mitre_aptname, str):
                mitre_aptname = str(mitre_aptname)
            for x in clean_aptname_list:
                self.db.insert_alias(mitre_aptname, x)
            for x in apt_name_list:
                self.db.insert_alias(mitre_aptname, x.lower())
            row_hash = hashlib.sha1((sheet_title + "_" + str(mitre_aptname)).encode('utf-8'))
            report_id = self.db.insert_report(row_hash.hexdigest(), "", "", "groups_and_operations_sheet")
            self.db.insert_apt_report_relation(mitre_aptname, report_id)
            self.db.connection.commit()
            links_columns = [x for x in current_row.keys() if x.startswith("Link")]
            links = [x.strip() for x in list(current_row[links_columns]) if x != ""]
            for current_url in links:
                self.__insert_repo_from_url__(mitre_aptname, current_url, "", "groups_and_operations_sheet")
            extracted_nations = self.deepLM.get_nations(target_string)
            for nation in extracted_nations:
                if nation in self.country_alias:
                    self.db.insert_organization(nation)
                    self.db.insert_apt_cos(mitre_aptname, nation)
            extracted_sector = self.deepLM.get_target(target_string)
            for sector in extracted_sector:
                self.db.insert_organization(sector)
                self.db.insert_apt_cos(mitre_aptname, sector)

    def aptGroupsOperations_update(self):
        for key in self.go_parser.sheets:
            current_sheet = self.go_parser.sheets[key]
            for elem in current_sheet.iterrows():
                current_row = elem[1]
                self.insert_gspread_alias(key, current_row)

    def aptnotes_update(self):
        old_reports = self.db.get_report_hashes()
        keywords_set = self.db.get_keywords()
        for report_row in self.aptnotes_parser.reports.iterrows():
            report = report_row[1]
            report_sha1 = report['SHA-1']
            if report_sha1 in old_reports:
                continue
            report_title = report['Title']
            report_link = report['Link']
            report_filename = report['Filename']
            report_path = self.downloader.download_from_appbox(report_link, report_filename)
            if report_path is None:
                continue
            try:
                report_data = parse_document(report_path, keywords_set, report_title)
            except Exception as e:
                self.db.insert_unknown_report(report_sha1, "", report_link, "APTNotes")
                continue
            if (report_data is None):
                self.db.insert_unknown_report(report_sha1, "", report_link, "APTNotes")
                continue
            hash_df = report_data["hash"]
            found_keywords = report_data["keyword"]
            if len(found_keywords) == 0:
                self.db.insert_unknown_report(report_sha1, "", report_link, "APTNotes")
                continue
            current_report_id = self.db.insert_report(report_sha1, report_title, report_link, "APTNotes",
                                                      found_keywords)
            self.db.connection.commit()
            if not hash_df.empty:
                for element in hash_df.iterrows():
                    current_sample = element[1]
                    sample_dict = current_sample.to_dict()
                    sample_id = self.db.insert_sample(sample_dict)
                    self.db.insert_sample_report_relation(sample_id, current_report_id)
                self.db.connection.commit()
            for current_type in ["url", "email", "ip"]:
                for address in report_data[current_type]:
                    self.db.insert_network(address, current_type)
                    self.insert_report_network_relation(current_report_id, address)
                self.db.connection.commit()

            for cve in report_data["cve"]:
                res = self.cve_parser.parse_cve(cve)
                self.db.insert_cve(res["name"], res["year"], res["affected_products"])
                self.db.insert_report_cve_relation(current_report_id, res["name"])
            self.db.connection.commit()

    def clean_hashes(self):
        hash_df = self.db.get_samples()
        for elem in hash_df.iterrows():
            if sum(elem[1].isna()) == 0:
                continue
            if sum(elem[1].isna()) == 1 and elem[1]["sha512"] is None:
                continue
            for hash_value in elem[1]:
                if hash_value is not None:
                    hashes = self.vt_parser.get_report(hash_value, "file", True)
                    self.db.update_sample(hashes)

    def software_search(self, malware=False):
        software_df = self.db.get_software()
        if (malware):
            selected_df = software_df[~software_df["is_tool"]]
        else:
            selected_df = software_df
        for current_elem in selected_df.iterrows():
            current_row = current_elem[1]
            current_name = current_row["software"]
            print(current_name)
            dict_list = self.ms_parser.search_by_name(current_name, True)
            for elem in dict_list:
                print(elem)
                labels = self.vt_parser.search_by_hash(elem["md5"], to_file=True, all_info=True)
                if (current_name in str(labels) or clean_string(current_name) in str(labels)):
                    sample_id = self.db.insert_sample(
                        {"md5": elem["md5"], "sha256": elem["sha256"], "sha1": elem["sha1"], "sha512": None})
                    self.db.insert_sample_report_relation(sample_id, current_row["report_id"])
            self.db.connection.commit()

    def clean_network(self):
        network_df = self.db.get_networks()
        for current_elem in network_df.iterrows():
            row = current_elem[1]
            result = self.vt_parser.get_report(row["address"], row["type"], True, True)
            if "url" in row["type"]:
                continue
            try:
                role = []
                for elem in result[(result["detected"] != False) & (result["detected"] != "clean site")].iterrows():
                    site_name = elem[0]
                    current_detection = elem[1]
                    role.append(site_name + ": " + str(current_detection["detected"]))
                if len(role) > 0:
                    self.db.update_network_role(row["address"], role)
            except Exception as e:
                print(result)
