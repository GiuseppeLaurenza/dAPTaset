#! /bin/python/env
import requests


class AbuseIPDB():

    def __init__(self, apikey):
        self.api_key = apikey

    def get_cat(x):
        return {
            3: 'Frad_Orders',
            4: 'DDoS_Attack',
            5: 'FTP_Brute-Force',
            6: 'Ping of Death',
            7: 'Phishing',
            8: 'Fraud VoIP',
            9: 'Open_Proxy',
            10: 'Web_Spam',
            11: 'Email_Spam',
            12: 'Blog_Spam',
            13: 'VPN IP',
            14: 'Port_Scan',
            15: 'Hacking',
            16: 'SQL Injection',
            17: 'Spoofing',
            18: 'Brute_Force',
            19: 'Bad_Web_Bot',
            20: 'Exploited_Host',
            21: 'Web_App_Attack',
            22: 'SSH',
            23: 'IoT_Targeted',
        }.get(
            x,
            'UNK CAT, ***REPORT TO MAINTAINER***OPEN AN ISSUE ON GITHUB w/ IP***')

    def abuse_check(self, IP, days):
        request = 'https://www.abuseipdb.com/check/%s/json?key=%s&days=%s' % (
            IP, self.api_key, days)
        # DEBUG
        # print(request)
        r = requests.get(request)
        # DEBUG
        # print(r.json())
        data = r.json()
        if not data:
            return ({'ip': IP, 'category': [], 'created': '', 'country': '',
                     'isoCode': '', 'isWhitelisted': False, 'abuseConfidenceScore': 0})
        return data

    # def get_report():
    #     # Convert category numbers to words
    #     if args.translate:
    #         for log in logs:
    #             tmp_catergory = []
    #             category = log['category']
    #             for cat in category:
    #                 tmp_catergory.append(get_cat(cat))
    #             log['category'] = tmp_catergory
    #
    #     # Output options
    #     if args.csv:
    #         keys = logs[0].keys()
    #         with open(args.csv, 'w') as outfile:
    #             dict_writer = csv.DictWriter(outfile, keys)
    #             dict_writer.writeheader()
    #             dict_writer.writerows(logs)
    #         pass
    #     elif args.tsv:
    #         keys = logs[0].keys()
    #         with open(args.tsv, 'w') as outfile:
    #             dict_writer = csv.DictWriter(outfile, keys, delimiter='\t')
    #             dict_writer.writeheader()
    #             dict_writer.writerows(logs)
    #         pass
    #     elif args.jsonl:
    #         json_logs = json.dumps(logs)
    #         with open(args.jsonl, 'w') as outfile:
    #             for log in logs:
    #                 json.dump(log, outfile)
    #                 outfile.write('\n')
    #         pass
    #     elif args.json:
    #         with open(args.json, 'w') as outfile:
    #             json.dump(logs, outfile)
    #         pass
    #     else:
    #         for log in logs:
    #             print(log)
    #         pass

    # def main():
    #     if args.days:
    #         days = args.days
    #     else:
    #         days = 30
    #
    #     if args.file:
    #         f = get_file(args.file)
    #         found = re.findall(
    #             r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', f)
    #
    #         list(found)
    #
    #         count = 0
    #         for ip in found:
    #             try:
    #                 socket.inet_aton(ip)
    #                 pass
    #             except socket.error:
    #                 continue
    #
    #             if ipaddress.ip_address(ip).is_private is False:
    #                 if count == 59:
    #                     time.sleep(60)
    #                     count = 0
    #                 abuse_check(ip, days)
    #                 count += 1
    #         get_report()
    #     elif args.ip:
    #         if ipaddress.ip_address(args.ip).is_private is False:
    #             abuse_check(args.ip, days)
    #             get_report()
    #         else:
    #             sys.exit("A Private IP will return no result...")
    #     else:
    #         sys.exit(
    #             "error: one of the following arguments are required: -f/--file or -i/--ip")

    #
    # if __name__ == '__main__':
    #     main()
