import configparser

from parser.APTGroupsOperationsParser import APTGroupsOperationsParser
from parser.APTNotesParser import APTNotesParser
from parser.MalshareParser import MalshareParser
from parser.MitreParser import MitreParser
from parser.VirusTotalParser import VirusTotalParser
from parser.cveParser import cveParser
from parser.mispGalaxyParser import mispGalaxyParser
from parser.restCountriesParser import restCountriesParser
from utilities.DatabaseWrapper import DatabaseWrapper
from utilities.Updater import Updater

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('config.ini')
    db = DatabaseWrapper(config._sections["Database"])
    mitre_parser = MitreParser(config["Paths"]["cti"])
    go_parser = APTGroupsOperationsParser(config["APT_Spreadsheet"]["url"])
    aptnotes_parser = APTNotesParser(config["APTNotes"]["url"])
    vt_parser = VirusTotalParser(config["VirusTotal"]["key"], config["VirusTotal"]["url"], config["Paths"]["temp"])
    ms_parser = MalshareParser(config["Malshare"]["key"], config["Malshare"]["url"], config["Paths"]["temp"])
    cve_parser = cveParser(config["Paths"]["cve"])
    country_parser = restCountriesParser(config["RestCountries"]["url"])
    galaxy_parser = mispGalaxyParser(config["mispGalaxy"]["threat_actor_url"])
    # galaxy_parser = None
    updater = Updater(db, mitre_parser, go_parser, aptnotes_parser, vt_parser, ms_parser, cve_parser, country_parser,
                      galaxy_parser,
                      config["Paths"]["temp"])
    # updater.mitre_update()
    # updater.misp_galaxy_update()
    updater.aptGroupsOperations_update()
    # updater.aptnotes_update()
    # updater.clean_hashes()
    # updater.software_search()
    # updater.clean_network()
    print("END")
