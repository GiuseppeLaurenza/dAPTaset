# Database Structure

This folder contains a copy of each table of our database as csv file and a dump of database schema exported from a PostgreSQL instance
In the following of this document we will describe all the tables with details on each column, columns in italic are part of the primary key; tables are divided in:
- [***Object Tables***](##Object-Tables)
- [***Relationships Tables***](##Relationships-Tables)
- [***Support Tables***](##Support-Tables)

## Object Tables
_______________
### APT
This table tracks the main name of each Advanced Persistent Threat
- ***apt_name*** (*text*, *not null*) contains a string representing the main name of an APT.
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the **created** field ath the creation of the record.
### REPORTS
This table tracks the parsed reports which can be linked to an APT
- ***report_id*** (*integer*, *not null*) is a numerical sequence to identify a record.
- **hash** (*text*, *unique*) is the SHA-1 of the report object, computed from parsed text or file object, depending to the report type.
- **url** (*text*, *unique*) is a string containing the url from which the report is downloaded.
- **description** (*text*) is a string containing a description of the report.
- **source** (*text*) is a string representing the source of the report.
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### COUNTRY_ORGANIZATION_SECTOR
This table contains all the countries, organizations and industrial sectors that can be related to APTs, like the suspected victim sector or the suspected state sponsor.
- ***name*** (*text*, *not null*) contains the name of the object
- **related_words** (*text*) contains a list of the words that can be related to the **name**, like synonyms or alternative naming words
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### CVE
This table tracks the *Common Vulnerabilities and Exposures* found in reports that one or more APTs exploit for their activities.
- ***cve*** (*text*, *not null*) contains the name of the cve.
- **year** (*integer*, *not null*) contains the year of the discovery of the vulnerability.
- **affected_products** (*text*) contains a list of the products affected by the vulnerability.
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### KEYWORDS
This table contains the list of words related to particular APTs, like alternative names, in order to allow an easy matching among different naming systems.
- ***keyword*** (*text*, *not null*) is a string representing the word.
- **is_alias** (*bool*, *not null*) is a flag to show if the current word is an alias of the APT.
- **apt_name** (*text*, FK to [*APT.apt_name*](###APT)) contains a string representing the main name of the related APT. 
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### NETWORK
This table stores all the network related IOCs found parsing report objects.
- **address** (*text*, *not null*) the string to store, it can be an URL, an IP address or an email address.
- ***address_hash*** (*text*, *not null*) is the hash of the *address* value, we use the hash as primary key instead of the entire field in order to improve indexing performance.
- **type** (*text*, *not null*) represents the type of the *address*, like if it is an IP address or a URL
- **role** (*text*, *not null*) represents why the *address* is tracked, like is the C2C IP address or the attacked email, the  default is "unknown"
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### SAMPLES
This table contains the list of binaries related to APTs.
- ***sample_id*** (*integer*, *not null*) is a sequence used to identify and indexing samples.
- **md5** (*text*, *unique*) contains the "md5" of the binary file.
- **sha1** (*text*, *unique*) contains the "sha1" of the binary file.
- **sha256** (*text*, *unique*) contains the "sha256" of the binary file.
- **sha512** (*text*, *unique*) contains the "sha512" of the binary file.
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### TECHNIQUES
- ***mitre_id*** (*text*, *not null*) text identifier.
- **name** (*text*, *not null*) represents the name of the technique
- **permissions_required** (*text*, *not null*) contains the list of the levels of permission required do be applied.
- **platforms** (*text*, *not null*) contains the list of operative systems that are targetable by this technique
- **tactics** (*text*) represents the name of the tactic phase which the technique belong.
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.

## Relationships Tables
_______________
### APT_COS
- ***apt_name*** (*text*, *not null*, FK to [*APT.apt_name*](###APT))
- ***country_organization_sector*** (*text*, *not null*, FK to [*COUNTRY_ORGANIZATION_SECTOR.name*](###COUNTRY_ORGANIZATION_SECTOR))
- **relation** (*text*, *not null*) contains the reason of the link between APT and the COUNTRY_ORGANIZATION_SECTOR, for example indicating that current APT has as suspected target this country.
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### APT_REPORT
- ***apt_name*** (*text*, *not null*, FK to [*APT.apt_name*](###APT))
- ***report_id*** (*integer*, *not null*, FK to [*REPORTS.report_id*](###REPORTS))
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### REPORT_CVE
- ***report_id*** (*integer*, *not null*, FK to [*REPORTS.report_id*](###REPORTS))
- ***cve*** (*text*, *not null*, FK to [*CVE.cve*](###CVE))
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### REPORT_NETWORK
- ***report_id*** (*integer*, *not null*, FK to [*REPORTS.report_id*](###REPORTS))
- ***address_hash*** (*text*, *not null*, FK to [*NETWORK.address_hash*](###NETWORK))
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### REPORT_TECHNIQUE
- ***report_id*** (*integer*, *not null*, FK to [*REPORTS.report_id*](###REPORTS))
- ***technique_id*** (*text*, *not null*, FK to [*TECHNIQUES.mitre_id*](###TECHNIQUES))
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
### SAMPLE_REPORT
- ***report_id*** (*integer*, *not null*, FK to [*REPORTS.report_id*](###REPORTS))
- ***sample_id*** (*text*, *not null*, FK to [*SAMPLES.sample_id*](###SAMPLES))
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.

## Support Tables
_______________
This tables are used to store temporary data that will be used by other functions in the future to improve the current database state.
### SOFTWARE
- ***software*** (*text*, *not null*) is a string containing the software name.
- **is_tool** (*bool*, *not null*) is a flag to distinguish between malware and tool groups.
- **report_id** (*integer*, *not null*, FK to [*REPORTS.report_id*](###REPORTS)) contains the identificaiton of the report in which the software name is found.
### UNKNOWN_REPORTS
This table tracks the parsed reports which cannot be linked to any of the APTs currently stored in database
- ***report_id*** (*integer*, *not null*) is a numerical sequence to identify a record.
- **hash** (*text*, *unique*) is the SHA-1 of the report object, computed from parsed text or file object, depending to the report type.
- **url** (*text*, *unique*) is a string containing the url from which the report is downloaded.
- **description** (*text*) is a string containing a description of the report.
- **source** (*text*) is a string representing the source of the report.
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.