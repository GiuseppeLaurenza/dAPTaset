import json

import pandas as pd
import psycopg2
from psycopg2._psycopg import IntegrityError

from utilities.string_functions import lowercase_nullcheck


class DatabaseWrapper:
    """This class wraps all the function for interacting with the database"""

    def __init__(self, connection_argument):
        self.connection = psycopg2.connect(user=connection_argument["user"], password=connection_argument["password"],
                                           host=connection_argument["host"], port=connection_argument["port"],
                                           database=connection_argument["database"])
        self.cursor = self.connection.cursor()

    def __del__(self):
        self.cursor.close()
        self.connection.close()

    def insert_apt_report_relation(self, apt_name, report_id):
        base_query = """ INSERT INTO "APT_REPORT" ("apt_name","report_id") VALUES (%s,%s)
        ON CONFLICT ON CONSTRAINT "APT_REPORT_pkey"
        DO NOTHING;"""
        full_query = self.cursor.mogrify(base_query, (apt_name, report_id))
        self.cursor.execute(full_query)

    def insert_report(self, hash_value, description, url, source, keywords_list=[]):
        base_query = """ INSERT INTO "REPORTS" ("hash","description","url","source") VALUES (%s,%s,%s,%s)
        ON CONFLICT ON CONSTRAINT "REPORTS_pkey"
        DO NOTHING
        RETURNING "report_id";"""
        full_query = self.cursor.mogrify(base_query,
                                         (hash_value.lower(), description.lower(), url.lower(), source.lower()))
        try:
            self.cursor.execute(full_query)
            report_id = self.cursor.fetchone()
            if isinstance(report_id, tuple):
                report_id = report_id[0]
        except psycopg2.IntegrityError as ie:
            if """Key ("URL")""" in ie.args[0]:
                self.connection.commit()
                base_query = """SELECT "hash","report_id" FROM "REPORTS" WHERE "url"=%s"""
                full_query = self.cursor.mogrify(base_query, [url.lower()])
                self.cursor.execute(full_query)
                report_data = self.cursor.fetchone()
                report_hash = report_data[0]
                report_id = report_data[1]
                if (report_hash != hash_value.lower()):
                    base_query = """update "REPORTS" set "hash"=%s where "url"=%s;"""
                    full_query = self.cursor.mogrify(base_query, (hash_value.lower(), url.lower()))
                    self.cursor.execute(full_query)
                    self.connection.commit()
            else:
                report_id = None
        if report_id is None:
            self.connection.commit()
            base_query = """SELECT "report_id" FROM "REPORTS" WHERE "hash"=%s"""
            full_query = self.cursor.mogrify(base_query, [hash_value.lower()])
            self.cursor.execute(full_query)
            report_id = self.cursor.fetchone()
        if report_id is None:
            self.connection.commit()
            base_query = """SELECT "report_id" FROM "REPORTS" WHERE "url"=%s"""
            full_query = self.cursor.mogrify(base_query, [url.lower()])
            self.cursor.execute(full_query)
            report_id = self.cursor.fetchone()
        if isinstance(report_id, tuple):
            report_id = report_id[0]
        self.connection.commit()
        for keyword in keywords_list:
            base_query = """SELECT "apt_name" FROM "KEYWORDS" WHERE "keyword"=%s"""
            full_query = self.cursor.mogrify(base_query, [keyword.lower()])
            self.cursor.execute(full_query)
            apt_name = self.cursor.fetchone()
            apt_name = apt_name[0]
            if (apt_name is not None):
                self.insert_apt_report_relation(apt_name, report_id)
            self.connection.commit()
        return report_id

    def insert_sample(self, hashes):
        for key in hashes:
            if hashes[key] is not None:
                if ("•" in hashes[key]):
                    hashes[key] = hashes[key].replace("•", "")
        base_query = """ INSERT INTO "SAMPLES" ("md5","sha1","sha256","sha512")
            VALUES (%s,%s,%s,%s)
            ON CONFLICT DO NOTHING
            RETURNING "sample_id" """
        full_query = self.cursor.mogrify(base_query,
                                         (lowercase_nullcheck(hashes["md5"]), lowercase_nullcheck(hashes["sha1"]),
                                          lowercase_nullcheck(hashes["sha256"]),
                                          lowercase_nullcheck(hashes["sha512"])))
        self.cursor.execute(full_query)
        result = self.cursor.fetchone()
        if (result is None):
            self.connection.commit()
            base_query = """SELECT "sample_id" FROM "SAMPLES" WHERE"""
            for key in hashes:
                if (hashes[key] is not None):
                    base_query += (""" \"""" + key.lower() + """\"=%s""")
                    full_query = self.cursor.mogrify(base_query, [hashes[key].lower()])
                    break
            self.cursor.execute(full_query)
            result = self.cursor.fetchone()
        return result[0]

    def update_sample(self, hashes):
        base_query = """SELECT * FROM "SAMPLES" WHERE"""
        result_list = []
        for key in hashes:
            if hashes[key] is None:
                continue
            if "•" in hashes[key]:
                hashes[key] = hashes[key].replace("•", "")
            partial_query = base_query + """ \"""" + key + """\"=%s"""
            full_query = self.cursor.mogrify(partial_query, [hashes[key].lower()])
            self.cursor.execute(full_query)
            result = self.cursor.fetchall()
            for elem in result:
                result_list.append(elem)
        if (len(result_list) > 1):
            sample_id = result_list[0][0]
            for elem in result_list[1:]:
                current_sample_id = elem[0]
                try:
                    partial_update_relation = """UPDATE "SAMPLE_REPORT"
                                    SET "sample_id"=%s WHERE "sample_id"=%s;"""
                    full_update_relation = self.cursor.mogrify(partial_update_relation, [sample_id, current_sample_id])
                    self.cursor.execute(full_update_relation)
                except IntegrityError as e:
                    self.connection.commit()
                    continue
                partial_update_relation = """DELETE FROM "SAMPLE_REPORT" WHERE "sample_id"=%s;"""
                full_update_relation = self.cursor.mogrify(partial_update_relation, [current_sample_id])
                self.cursor.execute(full_update_relation)
                self.connection.commit()
                parametric_delete_query = """DELETE FROM "SAMPLES" WHERE "sample_id"=%s;"""
                delete_query = self.cursor.mogrify(parametric_delete_query, [current_sample_id])
                self.cursor.execute(delete_query)
                self.connection.commit()

        if (len(result_list) > 0):
            first_element = result_list.pop(0)
            sample_id = first_element[0]
            partial_update_query = """UPDATE "SAMPLES" SET "md5"=%s,"sha1"=%s,"sha256"=%s,"sha512"=%s
            WHERE "sample_id"=%s;"""
            update_query = self.cursor.mogrify(partial_update_query,
                                               [hashes["md5"], hashes["sha1"], hashes["sha256"], hashes["sha512"],
                                                sample_id])
            try:
                self.cursor.execute(update_query)
            except IntegrityError as e:
                pass
            self.connection.commit()

    def insert_unknown_report(self, hash_value, description, url, source):
        base_query = """ INSERT INTO "UNKNOWN_REPORTS" ("hash","description","url","source") VALUES (%s,%s,%s,%s)
        ON CONFLICT DO NOTHING;"""
        full_query = self.cursor.mogrify(base_query,
                                         (hash_value.lower(), description.lower(), url.lower(), source.lower()))
        self.cursor.execute(full_query)

    def insert_sample_report_relation(self, sample_id, report_id):
        base_query = """INSERT INTO "SAMPLE_REPORT" ("sample_id", "report_id")
        VALUES(%s,%s)
        ON CONFLICT DO NOTHING;"""
        full_query = self.cursor.mogrify(base_query, (sample_id, report_id))
        self.cursor.execute(full_query)

    def insert_software(self, software_name, report_id, isTool):
        base_query = """INSERT INTO "SOFTWARE" ("software","report_id","is_tool")
        VALUES(%s,%s,%s)
        ON CONFLICT DO NOTHING"""
        full_query = self.cursor.mogrify(base_query, (software_name.lower(), report_id, isTool))
        self.cursor.execute(full_query)

    def insert_apt(self, apt_name):
        base_query = """ INSERT INTO "APT" ("apt_name") VALUES (%s)
        ON CONFLICT ON CONSTRAINT "APT_pkey"
        DO NOTHING;"""
        full_query = self.cursor.mogrify(base_query, (apt_name.lower(),))
        self.cursor.execute(full_query)

    def insert_alias(self, apt_name, alias):
        base_query = """ INSERT INTO "KEYWORDS" ("keyword","apt_name","is_alias") VALUES (%s,%s,%s)
            ON CONFLICT ON CONSTRAINT "KEYWORDS_pkey"
            DO UPDATE SET "is_alias"=EXCLUDED."is_alias" WHERE "KEYWORDS"."is_alias"=False;"""
        full_query = self.cursor.mogrify(base_query, (alias.lower(), apt_name.lower(), True))
        self.cursor.execute(full_query)

    def get_keywords(self):
        query = """ SELECT "keyword" FROM "KEYWORDS";"""
        self.cursor.execute(query)
        result_query = self.cursor.fetchall()
        keywords_set = set()
        for x in result_query:
            keywords_set.add(x[0])
        return keywords_set

    def get_samples(self):
        query = """ SELECT "md5","sha1","sha256","sha512" FROM "SAMPLES";"""
        self.cursor.execute(query)
        result_query = self.cursor.fetchall()
        result_df = pd.DataFrame(result_query, columns=["md5", "sha1", "sha256", "sha512"])
        return result_df

    def get_report_hashes(self):
        self.cursor.execute("""SELECT "hash" FROM "REPORTS" """)
        query_result = self.cursor.fetchall()
        old_reports = set()
        for elem in query_result:
            old_reports.add(elem[0])
        return old_reports

    def get_all_apt(self):
        self.cursor.execute("""SELECT "apt_name" FROM "APT" """)
        query_result = self.cursor.fetchall()
        old_reports = set()
        for elem in query_result:
            old_reports.add(elem[0])
        return old_reports

    def get_software(self):
        query = """ SELECT "software","report_id","is_tool" FROM "SOFTWARE";"""
        self.cursor.execute(query)
        result_query = self.cursor.fetchall()
        result_df = pd.DataFrame(result_query, columns=["software", "report_id", "is_tool"])
        return result_df

    def get_all_techniques(self):
        self.cursor.execute("""SELECT "mitre_id" FROM "TECHNIQUES" """)
        query_result = self.cursor.fetchall()
        old_techniques = set()
        for elem in query_result:
            old_techniques.add(elem[0])
        return old_techniques

    def insert_technique(self, techniques_dict):
        sql = "INSERT INTO \"TECHNIQUES\" (\"" + "\", \"".join(techniques_dict.keys()) + "\") VALUES (" + ", ".join(
            ["%(" + k + ")s" for k in techniques_dict]) + ") ON CONFLICT ON CONSTRAINT \"TECHNIQUES_pkey\" DO NOTHING;"
        full_query = self.cursor.mogrify(sql, techniques_dict)
        self.cursor.execute(full_query)
        self.connection.commit()

    def insert_report_technique(self, report_id, technique_id):
        sql = """INSERT INTO "REPORT_TECHNIQUE" ("report_id", "technique_id") VALUES (%s,%s)
                        ON CONFLICT DO NOTHING;"""
        full_query = self.cursor.mogrify(sql, (report_id, technique_id))
        self.cursor.execute(full_query)

    def insert_network(self, address, type, role=None):
        if not role:
            role = "unknown"
        sql = """INSERT INTO "NETWORK" ("address","type","role") VALUES (%s,%s,%s)
                ON CONFLICT DO NOTHING;"""
        full_query = self.cursor.mogrify(sql, (address.lower(), type.lower(), role.lower()))
        self.cursor.execute(full_query)
        self.connection.commit()

    def insert_report_network_relation(self, report_id, address):
        sql = """INSERT INTO "REPORT_NETWORK"("report_id","address") VALUES (%s,%s)
                ON CONFLICT DO NOTHING;"""
        full_query = self.cursor.mogrify(sql, (report_id, address.lower()))
        self.cursor.execute(full_query)

    def insert_cve(self, cve, year, affected_products):
        sql = """INSERT INTO "CVE" ("cve","year","affected_products") VALUES (%s,%s,%s)
                ON CONFLICT DO NOTHING; """
        full_query = self.cursor.mogrify(sql, (cve.upper(), year, affected_products))
        self.cursor.execute(full_query)
        self.connection.commit()

    def insert_report_cve_relation(self, report_id, cve):
        sql = """INSERT INTO "REPORT_CVE" ("report_id", "cve") VALUES (%s,%s)
                        ON CONFLICT DO NOTHING;"""
        full_query = self.cursor.mogrify(sql, (report_id, cve))
        self.cursor.execute(full_query)

    def get_networks(self):
        self.cursor.execute("""SELECT "address","type" FROM "NETWORK" WHERE "role"='unknown' AND "type"!='email' """)
        query_result = self.cursor.fetchall()
        result_df = pd.DataFrame(query_result, columns=["address", "type"])
        return result_df

    def update_network_role(self, address, role):
        base_query = """update "NETWORK" set "role"=%s where "address"=%s;"""
        full_query = self.cursor.mogrify(base_query, ([x.lower() for x in role], address.lower()))
        self.cursor.execute(full_query)
        self.connection.commit()

    def insert_organization(self, name, related_words=""):
        base_query = """ INSERT INTO "COUNTRY_ORGANIZATION_SECTOR" ("name","related_words") VALUES (%s,%s)
                    ON CONFLICT DO NOTHING;"""
        full_query = self.cursor.mogrify(base_query, (name, related_words))
        self.cursor.execute(full_query)
        self.connection.commit()

    def insert_apt_cos(self, apt_name, cos_name, relation=None):
        if relation is None:
            base_query = """ INSERT INTO "APT_COS" ("apt_name","country_organization_sector") VALUES (%s,%s)
                ON CONFLICT DO NOTHING;"""
            full_query = self.cursor.mogrify(base_query, (apt_name, cos_name))
            self.cursor.execute(full_query)
            self.connection.commit()
        else:
            try:
                base_query = """DELETE FROM "APT_COS" WHERE "apt_name"=%s and "country_organization_sector"=%s and "relation"='unknown';"""
                full_query = self.cursor.mogrify(base_query, (apt_name, cos_name))
                self.cursor.execute(full_query)
                self.connection.commit()
                base_query = """ INSERT INTO "APT_COS" ("apt_name","country_organization_sector","relation") VALUES (%s,%s,%s)
                    ON CONFLICT DO NOTHING;"""
                full_query = self.cursor.mogrify(base_query, (apt_name, cos_name, relation))
                self.cursor.execute(full_query)
                self.connection.commit()
            except psycopg2.IntegrityError as ie:
                self.connection.commit()

    def get_all_cos(self):
        self.cursor.execute("""SELECT "name","related_words" FROM "COUNTRY_ORGANIZATION_SECTOR"; """)
        query_result = self.cursor.fetchall()
        result_df = pd.DataFrame(query_result, columns=["name", "related_words"])
        result_df["related_works"] = result_df["related_works"].apply(lambda x: json.loads(x))
        return result_df
