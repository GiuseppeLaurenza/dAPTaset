import hashlib
import json

import pandas as pd
from git import Repo
from stix2 import FileSystemSource, CompositeDataSource, Filter
from stix2.utils import get_type_from_id


class MitreParser:
    """This class wraps all the function for interacting with the MitreAtt&ck Repository"""

    def __init__(self, cti_folder):
        self.cti_folder = cti_folder
        repo = Repo(cti_folder)
        origin = repo.remotes.origin
        try:
            origin.pull()
        except Exception as e:
            pass
        enterprise_attack_fs = FileSystemSource(cti_folder + "enterprise-attack")
        pre_attack_fs = FileSystemSource(cti_folder + "pre-attack")
        mobile_attack_fs = FileSystemSource(cti_folder + "mobile-attack")
        self.src = CompositeDataSource()
        self.src.add_data_sources([enterprise_attack_fs, pre_attack_fs, mobile_attack_fs])
        # self.columns_list = {"techniques":['mitre_id', 'name', 'description', 'permissions_required', 'platforms', 'adversary-opsec', 'build-capabilities', 'collection', 'command-and-control', 'compromise', 'credential-access', 'defense-evasion', 'discovery', 'effects', 'establish-&-maintain-infrastructure', 'execution', 'exfiltration', 'impact', 'initial-access', 'lateral-movement', 'launch', 'network-effects', 'organizational-information-gathering', 'organizational-weakness-identification', 'people-information-gathering', 'people-weakness-identification', 'persistence', 'persona-development', 'priority-definition-direction', 'priority-definition-planning', 'privilege-escalation', 'remote-service-effects', 'stage-capabilities', 'target-selection', 'technical-information-gathering', 'technical-weakness-identification', 'test-capabilities','kill_chain_phases']}
        self.columns_list = {
            "techniques": ['mitre_id',
                           'tactics',
                           'name',
                           'permissions_required',
                           'platforms']}


    def get_technique_by_group(self, stix_id):
        relations = self.src.relationships(stix_id, 'uses', source_only=True)
        return self.src.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('id', 'in', [r.target_ref for r in relations])
        ])

    def get_malware_by_group(self, stix_id):
        relations = self.src.relationships(stix_id, 'uses', source_only=True)
        query_malware = self.src.query([
            Filter('type', '=', 'malware'),
            Filter('id', 'in', [r.target_ref for r in relations])
        ])
        dict_malware = []
        for group in query_malware:
            string_report = group.serialize()
            dict_report = json.loads(string_report)
            dict_malware.append(dict_report)
        df_malware = pd.DataFrame(dict_malware)
        return df_malware

    def get_tool_by_group(self, stix_id):
        relations = self.src.relationships(stix_id, 'uses', source_only=True)
        query_tool = self.src.query([
            Filter('type', '=', 'tool'),
            Filter('id', 'in', [r.target_ref for r in relations])
        ])
        dict_tool = []
        for group in query_tool:
            string_report = group.serialize()
            dict_report = json.loads(string_report)
            dict_tool.append(dict_report)
        df_tool = pd.DataFrame(dict_tool)
        return df_tool

    def get_techniques_by_group(self, stix_id):
        group_uses = [
            r for r in self.src.relationships(stix_id, 'uses', source_only=True)
            if get_type_from_id(r.target_ref) in ['malware', 'tool']
        ]

        software_uses = self.src.query([
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', 'uses'),
            Filter('source_ref', 'in', [r.source_ref for r in group_uses])
        ])

        techniques_query = self.src.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('id', 'in', [r.target_ref for r in software_uses])
        ])
        dict_techniques = []
        for current_technique in techniques_query:
            string_report = current_technique.serialize()
            dict_report = json.loads(string_report)
            dict_techniques.append(dict_report)
        techniques_df = pd.DataFrame(dict_techniques)
        if techniques_df.empty:
            return techniques_df
        techniques_df = techniques_df.fillna("")
        techniques_df["kill_chain_phases"] = techniques_df["kill_chain_phases"].apply(
            lambda x: [y["phase_name"] for y in x if 'mitre' in y['kill_chain_name']])
        techniques_df = techniques_df.rename(index=str, columns={"x_mitre_permissions_required": "permissions_required",
                                                                 "x_mitre_platforms": "platforms", "id": "mitre_id",
                                                                 "kill_chain_phases": "tactics"})
        column_set = set(techniques_df.columns.values)
        for i in self.columns_list["techniques"]:
            column_set.add(i)
        techniques_df = techniques_df.reindex(columns=list(column_set), fill_value="")
        return techniques_df[self.columns_list["techniques"]]

    def get_group_by_alias(self, alias):
        return self.src.query([
            Filter('type', '=', 'intrusion-set'),
            Filter('aliases', '=', alias)
        ])

    def get_all_groups(self):
        filt = Filter('type', '=', 'intrusion-set')
        groups = self.src.query([filt])
        dict_groups = []
        for group in groups:
            string_report = group.serialize()
            dict_report = json.loads(string_report)
            hash_report = hashlib.sha1(string_report.encode('utf-8')).hexdigest()
            dict_report["hash"] = hash_report
            dict_groups.append(dict_report)
        group_df = pd.DataFrame(dict_groups)
        group_df = group_df.fillna("")
        return group_df

    def get_all_techniques(self):
        technique_query = self.src.query(Filter('type', '=', 'attack-pattern'))
        dict_techniques = []
        for current_technique in technique_query:
            string_report = current_technique.serialize()
            dict_report = json.loads(string_report)
            dict_techniques.append(dict_report)
        techniques_df = pd.DataFrame(dict_techniques)
        techniques_df = techniques_df.fillna("")
        techniques_df["kill_chain_phases"] = techniques_df["kill_chain_phases"].apply(
            lambda x: [y["phase_name"] for y in x if 'mitre' in y['kill_chain_name']])
        techniques_df = techniques_df.rename(index=str, columns={"x_mitre_permissions_required": "permissions_required",
                                                                 "x_mitre_platforms": "platforms", "id": "mitre_id"})
        return techniques_df[self.columns_list["techniques"]]

    def get_all_tactics(self):
        tactic_query = self.src.query(Filter('type', '=', 'x-mitre-tactic'))
        tactics_df = pd.DataFrame(tactic_query)
        return tactics_df
