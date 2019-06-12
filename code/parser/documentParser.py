import re
from string import punctuation
from unicodedata import normalize

import magic
import pandas as pd
# from utilities import iocextract
from PyPDF2 import PdfFileReader
from bs4 import BeautifulSoup
# from ioc_finder import find_iocs
from msticpy.sectools import IoCExtract


def parse_document(document_path, keywords=[], report_title=None):
    file_type = magic.from_file(document_path).lower()
    keywords_argument = []
    title = []
    if ("pdf" in file_type):
        with open(document_path, "rb") as f:
            pdf = PdfFileReader(f)
            parsedDocument = pdf.getDocumentInfo()
            number_of_pages = pdf.getNumPages()
            raw_text = ""
            for i in range(0, number_of_pages):
                current_page = pdf.getPage(i)
                try:
                    current_text = current_page.extractText()
                except Exception as e:
                    continue
                raw_text = raw_text + current_text
            for elem in parsedDocument.keys():
                if isinstance(parsedDocument[elem], dict):
                    for key in parsedDocument[elem]:
                        if ("key" in key.lower()):
                            keywords_argument = parsedDocument[elem][key]
                        if ("title" in key.lower()):
                            title = parsedDocument[elem][key]
                        if isinstance(parsedDocument[elem][key], dict):
                            for key2 in parsedDocument[elem][key]:
                                if ("key" in key2.lower()):
                                    keywords_argument = parsedDocument[elem][key][key2]
                                if ("title" in key.lower()):
                                    title = parsedDocument[elem][key][key2]
    elif ("html" in file_type):
        with open(document_path, "rb") as html:
            tree = BeautifulSoup(html, 'lxml')
            body = tree.body
            if body is None:
                return None
            for tag in body.select('script'):
                tag.decompose()
            for tag in body.select('style'):
                tag.decompose()
            raw_text = body.get_text(separator='\n')
            title = tree.title.string
    else:
        return None

    # if ('content' not in parsedDocument):
    #     return None
    if (raw_text is None) or len(raw_text)==0:
        return None
    raw_text = raw_text.lower()
    remove_punct_map = dict.fromkeys(map(ord, punctuation))
    text = raw_text.translate(remove_punct_map)
    text = text.replace("\n\n", " ").replace("\n", " ").replace("•", "").replace("  ", " ")
    result = pd.DataFrame(columns={"md5", "sha1", "sha256", "sha512"})
    keywords_list = []
    keywords_title = []
    for elem in title:
        if (elem in keywords):
            keywords_title.append(elem)
    if report_title is not None:
        for elem in report_title:
            if (elem in keywords):
                keywords_title.append(elem)
    for elem in keywords_argument:
        if (elem in keywords):
            keywords_title.append(elem)
    ioc_extractor = IoCExtract()
    ioc_extractor.add_ioc_type(ioc_type="cves", ioc_regex="CVE-\d{4}-\d{4,7}")
    ioc_extractor.add_ioc_type(ioc_type="email", ioc_regex=r'[\w\.-]+@[\w\.-]+(\.[\w]+)+')

    iocextract_result = ioc_extractor.extract(raw_text)
    url_list = set(
        [normalize('NFKD', x).encode('ASCII', 'ignore').decode('ASCII', 'ignore') for x in iocextract_result["url"] if
         not normalize('NFKD', x).encode('ASCII', 'ignore').endswith(b"-")])
    ip_list = set([x for x in iocextract_result["ip"] if not x.startswith(('192.168.', '10.', '172.16.', '172.31.'))])
    email = set(iocextract_result["email"])
    for elem in (
    [{"md5": hash, "sha1": None, "sha256": None, "sha512": None} for hash in iocextract_result["md5_hash"]]):
        result = result.append(elem, ignore_index=True)

    for elem in (
    [{"md5": None, "sha1": hash, "sha256": None, "sha512": None} for hash in iocextract_result["sha1_hash"]]):
        result = result.append(elem, ignore_index=True)

    for elem in (
    [{"md5": None, "sha1": None, "sha256": hash, "sha512": None} for hash in iocextract_result["sha256_hash"]]):
        result = result.append(elem, ignore_index=True)

    for elem in (
    [{"md5": None, "sha1": None, "sha256": None, "sha512": hash} for hash in iocextract_result["sha512_hash"]]):
        result = result.append(elem, ignore_index=True)

    cve_list = set(iocextract_result["cves"])

    if len(keywords_title) == 0:
        for elem in keywords:
            if re.search(r'\b({})\b'.format(elem), text):
                keywords_list.append(elem)
    return {"keyword": keywords_list, "hash": result, "email": email, "ip": ip_list, "url": url_list, "cve": cve_list}
