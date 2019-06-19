# Database Structure
This folder contains a copy of each table of our database as csv file and a dump of database schema exported from a PostgreSQL instance
In the following of this document we will describe all the tables with details on each column, columns in italic are part of the primary key.

## Object Table
### APT
This table tracks the main name of each Advanced Persistent Threat
- ***apt_name*** (*text*, *not null*) contains a string representing the main name of an APT.
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.

### REPORTS
This table tracks the parsed reports which can be linked to an APT
- ***report_id*** (*integer*, *not null*) is a numerical sequence to identify a record.
- **hash** (*text*, *unique*) is the SHA-1 of the report object, computed from parsed text or file object, depending to the report type.
- **url** (*text*, *unique*) is a string containing the url from which the report is downloaded.
- **description** (*text*) is a string containing a description of the report.
- **source** (*text*) is a string representing the source of the report.
- **created** (*timestamp*, *not null*) contanins the time of the creation of the record.
- **last_update** (*timestamp*, *not null*) contains the time of the last modification of the record, it is equal to the *created* field ath the creation of the record.
