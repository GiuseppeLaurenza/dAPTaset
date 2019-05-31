import json
from os import scandir

from git import Repo


class cveParser():
    def __init__(self, cve_folder):
        repo = Repo(cve_folder)
        origin = repo.remotes.origin
        origin.pull()
        self.folder = cve_folder

    def parse_cve(self, cve):
        year = cve.split("-")[1]

        for entry in scandir(self.folder + year + "/"):
            for subfolder in scandir(self.folder + year + "/" + entry.name):
                if cve in subfolder.path:
                    with open(subfolder.path, "r") as infile:
                        data = json.load(infile)
                        product_list = []
                        affects = data.get("affects", None)
                        if not affects:
                            affects = data.get("affect", None)
                            if not affects:
                                break
                        for elem in data["affects"]["vendor"]["vendor_data"]:
                            for product_data in elem["product"]["product_data"]:
                                product_list.append(product_data["product_name"])
                        if 'n/a' in product_list:
                            product_list = None
                        return {"name": cve, "year": year, "affected_products": product_list}
        return {"name": cve, "year": year, "affected_products": None}
